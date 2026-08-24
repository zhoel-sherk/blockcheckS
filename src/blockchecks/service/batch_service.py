"""Boot a batch, probe each item, shut down. Backends: classic or lua_bridge."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from blockchecks.checkers.curl_probe import is_googlevideo_domain, is_ytcdn_domain
from blockchecks.service import live_events
from blockchecks.service.batch_bridge_probe import run_tcp_check_bridge
from blockchecks.service.batch_models import (
    BatchContext,
    BatchProbeConfig,
    BatchProbeResult,
    RunnerProbeDeps,
)
from blockchecks.service.batch_scheduler import BatchScheduler
from blockchecks.service.lua_bridge_ipc import LuaBridge
from blockchecks.service.lua_netns import _netns_tcp_probe_cleanup
from blockchecks.service.lua_session import BridgeSession, strategy_text_from_item
from blockchecks.terminal import CYAN, RESET, YELLOW

log = logging.getLogger(__name__)

#: Max seconds to wait for a free netns before bailing out of a batch. Prevents
#: a graceful stop (or a hung batch holding the whole pool) from deadlocking
#: the adaptive/bridge workers on an empty pool queue.
ACQUIRE_NS_TIMEOUT = 30.0


def _debug_env() -> str:
    """Current nfqws2 --debug env value ('' when disabled)."""
    return os.environ.get("BLOCKCHECKS_NFQWS2_DEBUG", "").strip()


class ProbeBatchService:
    """Boot batch → probe ×N → shutdown with classic or lua_bridge backend."""

    def __init__(
        self,
        config: BatchProbeConfig,
        deps: RunnerProbeDeps,
        memory_monitor=None,
    ) -> None:
        self.config = config
        self.deps = deps
        self.scheduler = BatchScheduler(config.batch_size)
        self.memory_monitor = memory_monitor

    async def run_batch(
        self,
        ctx: BatchContext,
        timeout: float,
        stop_event: asyncio.Event | None = None,
    ) -> BatchProbeResult:
        # Do not acquire a namespace when a graceful stop is already requested —
        # otherwise a stopped run hangs waiting for a busy pool.
        if stop_event is not None and stop_event.is_set():
            return self._empty_stopped_result(ctx)
        # Bound the acquisition: if every netns is busy (e.g. a hung batch holds
        # the pool), wait_for lets us bail out instead of deadlocking the stop.
        try:
            ns = await asyncio.wait_for(self.deps.acquire_ns(), timeout=ACQUIRE_NS_TIMEOUT)
        except asyncio.TimeoutError:
            return self._empty_stopped_result(ctx)
        try:
            domains = ctx.item_domains()
            resolved_by_domain: dict[str, tuple[str | None, str, str]] = {}
            ip_lists_by_domain: dict[str, list[str]] = {}
            for d in dict.fromkeys(domains):
                resolved_by_domain[d] = await self.deps.resolve_domain_dns(d)
                ip_lists_by_domain[d] = self.deps.resolve_domain_ips(d)
            if stop_event is not None and stop_event.is_set():
                return self._empty_stopped_result(ctx)
            wall_start = time.monotonic()
            sync_task: asyncio.Task | None = None
            try:
                sync_task = asyncio.create_task(
                    asyncio.to_thread(
                        self._run_batch_sync,
                        ctx,
                        timeout,
                        ns,
                        resolved_by_domain,
                        ip_lists_by_domain,
                        stop_event,
                    )
                )
                result = await sync_task
            except asyncio.CancelledError:
                # to_thread keeps running after cancel — wait before releasing ns.
                if sync_task is not None and not sync_task.done():
                    try:
                        await sync_task
                    except Exception:
                        pass
                raise
            except Exception as e:
                # Never lose the batch: any error in the sync probe loop must
                # still produce per-item failure results + DB logging.
                failed = self._batch_fail_results(ctx, str(e))
                result = BatchProbeResult(
                    results=failed,
                    settle_ms=0,
                    backend=self.config.backend,
                    batch_wall_ms=(time.monotonic() - wall_start) * 1000,
                    batch_fill_ratio=0,
                )
            result.batch_wall_ms = (time.monotonic() - wall_start) * 1000
            result.batch_fill_ratio = len(ctx.items) / max(1, self.config.batch_size)
            for item, dom, probe_result in zip(ctx.items, domains, result.results, strict=False):
                resolved_ip, dns_verdict, doh_server = resolved_by_domain[dom]
                await self.deps.log_tcp_result(
                    item,
                    dom,
                    probe_result,
                    resolved_ip=resolved_ip,
                    dns_verdict=dns_verdict,
                    doh_server=doh_server,
                )
            self._log_batch(ctx, ns, result)
            return result
        finally:
            await self.deps.release_ns(ns)

    @staticmethod
    def _empty_stopped_result(ctx: BatchContext) -> BatchProbeResult:
        """Empty result when a stop was requested before the batch started."""
        from blockchecks.engine.results import TcpTestResult

        results = [
            TcpTestResult(
                item=item,
                domain=dom,
                success=False,
                error="stopped before probe",
            )
            for item, dom in zip(ctx.items, ctx.item_domains(), strict=False)
        ]
        return BatchProbeResult(
            results=results,
            settle_ms=0,
            backend="",
            batch_wall_ms=0,
            batch_fill_ratio=0,
        )

    def _run_batch_sync(
        self,
        ctx: BatchContext,
        timeout: float,
        ns_name: str,
        resolved_by_domain: dict[str, tuple[str | None, str, str]],
        ip_lists_by_domain: dict[str, list[str]] | None = None,
        stop_event: asyncio.Event | None = None,
    ) -> BatchProbeResult:
        if self.config.backend == "lua_bridge":
            return self._run_lua_bridge_batch(
                ctx, timeout, ns_name, resolved_by_domain, ip_lists_by_domain, stop_event
            )
        return self._run_classic_batch(
            ctx, timeout, ns_name, resolved_by_domain, ip_lists_by_domain, stop_event
        )

    def _run_classic_batch(
        self,
        ctx: BatchContext,
        timeout: float,
        ns_name: str,
        resolved_by_domain: dict[str, tuple[str | None, str, str]],
        ip_lists_by_domain: dict[str, list[str]] | None = None,
        stop_event: asyncio.Event | None = None,
    ) -> BatchProbeResult:
        results: list = []
        for item, dom in zip(ctx.items, ctx.item_domains(), strict=False):
            if stop_event is not None and stop_event.is_set():
                break
            timeout_i, settle_max = self.deps.timing_for(item, timeout)
            protocol = getattr(item, "protocol", ctx.protocol) or ctx.protocol
            resolved_ip, _, _ = resolved_by_domain[dom]
            live_events.set_current(
                domain=dom,
                strategy=getattr(item, "label", item.strategy),
                ns=ns_name,
                backend="classic",
            )
            data = self.deps.run_tcp_check(
                ns_name,
                item.strategy,
                dom,
                timeout_i,
                item.is_config,
                self.deps.python,
                self.deps.disable_ech,
                resolved_ip,
                self.deps.repeats,
                self.deps.parallel_repeats,
                "",
                protocol,
                settle_max,
                None,
                self.deps.repeats_mode,
                self.deps.quick_break,
                resolved_ips=(ip_lists_by_domain or {}).get(dom),
            )
            data = self._maybe_wssize_retry(
                item,
                ctx,
                timeout_i,
                ns_name,
                resolved_ip,
                protocol,
                settle_max,
                data,
                ip_lists=(ip_lists_by_domain or {}).get(dom),
            )
            data["batch_id"] = ctx.batch_id
            result = self.deps.tcp_result_from_data(item, dom, data)
            live_events.write_probe(
                domain=dom,
                strategy=getattr(item, "label", item.strategy),
                ns=ns_name,
                backend="classic",
                status=(
                    "THROTTLED" if result.throttled
                    else ("PASS" if result.success else "FAIL")
                ),
                http_code=result.http_code,
                latency_ms=result.latency_ms,
                applied=result.bridge_applied,
            )
            results.append(result)
        _netns_tcp_probe_cleanup(ns_name)
        return BatchProbeResult(
            results=results,
            settle_ms=0.0,
            backend="classic",
        )

    def _batch_fail_results(self, ctx: BatchContext, error: str) -> list:
        results = []
        for item, dom in zip(ctx.items, ctx.item_domains(), strict=False):
            data = {"success": False, "error": error, "batch_id": ctx.batch_id}
            result = self.deps.tcp_result_from_data(item, dom, data)
            results.append(result)
        return results

    def _run_lua_bridge_batch(
        self,
        ctx: BatchContext,
        timeout: float,
        ns_name: str,
        resolved_by_domain: dict[str, tuple[str | None, str, str]],
        ip_lists_by_domain: dict[str, list[str]] | None = None,
        stop_event: asyncio.Event | None = None,
    ) -> BatchProbeResult:
        protocol = ctx.protocol
        if ctx.items:
            protocol = getattr(ctx.items[0], "protocol", ctx.protocol) or ctx.protocol
        strat_lines = [strategy_text_from_item(item) for item in ctx.items]
        session = BridgeSession(
            ns_name=ns_name,
            strategies=strat_lines,
            bridge=LuaBridge(ns_name),
            protocol=protocol,
            extra_lua_init=self.deps.lua_extra or None,
        )
        results: list = []
        settle_ms = 0.0
        recycled = 0
        try:
            settle_ms = session.boot() * 1000
            self._bridge_ready_fence(session, ctx, timeout, resolved_by_domain)
            boot_debug = _debug_env()
            self._record_daemon_mem(ns_name)
            for idx, (item, dom) in enumerate(
                zip(ctx.items, ctx.item_domains(), strict=False), start=1
            ):
                if stop_event is not None and stop_event.is_set():
                    break
                if self._maybe_recycle(ns_name, session):
                    recycled += 1
                    boot_debug = _debug_env()
                elif _debug_env() != boot_debug:
                    # SIGUSR1 toggled nfqws2 --debug while this batch was running:
                    # restart the daemon so the next probe picks it up.
                    log.info(
                        "%s",
                        f"  {YELLOW}[debug] restarting nfqws2 in {ns_name} "
                        f"(debug={'1' if _debug_env() else '0'}){RESET}",
                    )
                    session.boot()
                    boot_debug = _debug_env()
                    recycled += 1
                elif self._daemon_heartbeat_stale(session):
                    # Heartbeat stale (Lua timer silent > ~3s): daemon is dead
                    # or wedged — reboot proactively instead of burning a curl
                    # timeout on queue-bypassed clean traffic.
                    log.warning(
                        "%s",
                        f"  {YELLOW}[bridge] heartbeat stale in {ns_name} — "
                        f"rebooting daemon before probe{RESET}",
                    )
                    session.boot()
                    recycled += 1
                gen = self.deps.next_probe_gen()
                timeout_i, _ = self.deps.timing_for(item, timeout)
                item_proto = getattr(item, "protocol", protocol) or protocol
                resolved_ip, _, _ = resolved_by_domain[dom]
                live_events.set_current(
                    domain=dom,
                    strategy=getattr(item, "label", item.strategy),
                    ns=ns_name,
                    backend="lua_bridge",
                )
                data = run_tcp_check_bridge(
                    session,
                    idx,
                    gen,
                    item.strategy,
                    dom,
                    timeout_i,
                    self.deps.python,
                    self.deps.disable_ech,
                    resolved_ip,
                    self.deps.repeats,
                    self.deps.parallel_repeats,
                    "",
                    item_proto,
                    self.deps.repeats_mode,
                    self.deps.quick_break,
                    resolved_ips=(ip_lists_by_domain or {}).get(dom),
                )
                if _bridge_silent(data) and isinstance(data, dict):
                    # Zero bridge activity means the daemon died mid-batch (a
                    # live scan_pick ALWAYS emits APPLIED on tls_client_hello).
                    # Without this retry the rest of the batch runs clean
                    # (queue-bypass) and unblocked domains record false PASSes.
                    log.warning(
                        "%s",
                        f"  {YELLOW}[bridge] zero events for {getattr(item, 'label', '?')[:24]} "
                        f"in {ns_name} — daemon presumed dead, rebooting and retrying once"
                        f"{RESET}",
                    )
                    session.boot()
                    gen = self.deps.next_probe_gen()
                    data = run_tcp_check_bridge(
                        session,
                        idx,
                        gen,
                        item.strategy,
                        dom,
                        timeout_i,
                        self.deps.python,
                        self.deps.disable_ech,
                        resolved_ip,
                        self.deps.repeats,
                        self.deps.parallel_repeats,
                        "",
                        item_proto,
                        self.deps.repeats_mode,
                        self.deps.quick_break,
                        resolved_ips=(ip_lists_by_domain or {}).get(dom),
                    )
                data["batch_id"] = ctx.batch_id
                result = self.deps.tcp_result_from_data(item, dom, data)
                live_events.write_probe(
                    domain=dom,
                    strategy=getattr(item, "label", item.strategy),
                    ns=ns_name,
                    backend="lua_bridge",
                    status=(
                        "THROTTLED" if result.throttled
                        else ("PASS" if result.success else "FAIL")
                    ),
                    http_code=result.http_code,
                    latency_ms=result.latency_ms,
                    applied=result.bridge_applied,
                )
                results.append(result)
        finally:
            session.shutdown()
        return BatchProbeResult(
            results=results,
            settle_ms=settle_ms,
            backend="lua_bridge",
        )

    def _daemon_heartbeat_stale(self, session: BridgeSession, max_age: float = 3.0) -> bool:
        """True when the Lua heartbeat is missing/stale — daemon dead or wedged.

        The heartbeat timer rewrites the file every ~200ms, so anything above
        ~3s means no live event loop in nfqws2. Probing then would only burn
        curl timeout on queue-bypassed clean traffic.
        """
        try:
            age = session.bridge.heartbeat_age()
        except Exception:
            return False
        if not isinstance(age, (int, float)):
            return False
        return age > max_age

    def _bridge_ready_fence(
        self,
        session: BridgeSession,
        ctx: BatchContext,
        timeout: float,
        resolved_by_domain: dict[str, tuple[str | None, str, str]],
    ) -> None:
        """Verify the freshly booted daemon actually applies strategies.

        settle only waits for process visibility (/proc), but under load Lua
        init (3 scripts + plan build) and the NFQUEUE bind can lag behind —
        early probes then leave the netns clean (queue-bypass) producing
        false "PASS without APPLIED" rows. Fire one synthetic probe against
        the batch's first domain; require ANY bridge event. On silence,
        reboot the daemon once and retry; give up with a loud warning.
        """
        if not ctx.items:
            return
        if self._daemon_heartbeat_stale(session):
            # Heartbeat already stale right after boot: skip the synthetic
            # probe and reboot immediately.
            log.warning(
                "%s",
                f"  {YELLOW}[bridge] heartbeat stale in {session.ns_name} "
                f"right after boot — rebooting before fence{RESET}",
            )
            session.boot()
        # Fence against the first plain-TLS domain: googlevideo/ytcdn probes
        # need signed URLs / special prep and can legitimately produce no
        # bridge events, which would trip the reboot logic.
        dom = ""
        resolved_ip = None
        for item, d in zip(ctx.items, ctx.item_domains(), strict=False):
            proto_i = getattr(item, "protocol", ctx.protocol) or ctx.protocol
            if proto_i != "tls12" or is_googlevideo_domain(d) or is_ytcdn_domain(d):
                continue
            dom = d
            resolved_ip = resolved_by_domain.get(d, (None, "", ""))[0]
            break
        if not dom:
            return
        protocol = getattr(ctx.items[0], "protocol", ctx.protocol) or ctx.protocol
        # Fence is best-effort: never let it kill the batch. Any internal
        # error here is logged loudly and skips the check.
        try:
            strat_text = (getattr(session, "strategies", None) or [""])[0]
            gen = self.deps.next_probe_gen()
            fence_timeout = min(timeout, 1.5)
            data = run_tcp_check_bridge(
                session,
                1,
                gen,
                strat_text,
                dom,
                fence_timeout,
                self.deps.python,
                self.deps.disable_ech,
                resolved_ip,
                1,
                False,
                "",
                protocol,
                "fast",
                False,
            )
        except Exception as exc:  # noqa: BLE001 — fence must not break probing
            log.warning(
                "%s",
                f"  {YELLOW}[bridge] readiness fence errored ({exc}) — skipping check{RESET}",
            )
            return
        # Non-dict responses come from test doubles / exotic backends:
        # treat them as ready instead of rebooting (keeps mock semantics).
        if not isinstance(data, dict):
            return
        events = data.get("bridge_events") or []
        if data.get("bridge_applied") or events:
            return
        log.warning(
            "%s",
            f"  {YELLOW}[bridge] readiness fence silent in {session.ns_name} "
            f"— rebooting daemon and retrying{RESET}",
        )
        session.boot()
        try:
            gen2 = self.deps.next_probe_gen()
            data2 = run_tcp_check_bridge(
                session,
                1,
                gen2,
                strat_text,
                dom,
                fence_timeout,
                self.deps.python,
                self.deps.disable_ech,
                resolved_ip,
                1,
                False,
                "",
                protocol,
                "fast",
                False,
            )
        except Exception as exc:  # noqa: BLE001 — fence must not break probing
            log.warning(
                "%s",
                f"  {YELLOW}[bridge] readiness retry errored ({exc}) — skipping check{RESET}",
            )
            return
        if not isinstance(data2, dict):
            return
        events2 = data2.get("bridge_events") or []
        if data2.get("bridge_applied") or events2:
            return
        log.warning(
            "%s",
            f"  {YELLOW}[bridge] daemon in {session.ns_name} unresponsive to fence — "
            f"probes may run clean (queue-bypass){RESET}",
        )

    def _record_daemon_mem(self, ns_name: str) -> None:
        if self.memory_monitor is None or self.config.backend != "lua_bridge":
            return
        if not self.memory_monitor.should_sample():
            return
        self.memory_monitor.record_ns(ns_name)
        if self.memory_monitor.worker_over_limit():
            log.info(
                "%s",
                f"  {YELLOW}[mem] python worker RSS over threshold "
                f"(see BLOCKCHECKS_MEM_PY_MAX_MIB){RESET}",
            )

    def _maybe_recycle(self, ns_name: str, session: BridgeSession) -> bool:
        """Recycle the nfqws2 daemon when the memory monitor flags a leak."""
        if self.memory_monitor is None or self.config.backend != "lua_bridge":
            return False
        self._record_daemon_mem(ns_name)
        candidates = self.memory_monitor.recycle_candidates()
        if not candidates:
            return False
        for pid, reason in candidates:
            self.memory_monitor.clear(pid)
            log.info(
                "%s", f"  {YELLOW}[mem] recycle nfqws2 pid={pid} ({reason}) in {ns_name}{RESET}"
            )
        session.boot()
        self._record_daemon_mem(ns_name)
        return True

    def _maybe_wssize_retry(
        self,
        item,
        ctx: BatchContext,
        timeout_i: float,
        ns_name: str,
        resolved_ip: str | None,
        protocol: str,
        settle_max: float | None,
        data: dict,
        *,
        ip_lists: list[str] | None = None,
    ) -> dict:
        if (
            not data.get("success")
            and self.deps.try_wssize
            and protocol == "tls12"
            and not item.is_config
            and "wssize" not in item.strategy
        ):
            return self.deps.run_tcp_check(
                ns_name,
                item.strategy,
                ctx.domain,
                timeout_i,
                item.is_config,
                self.deps.python,
                self.deps.disable_ech,
                resolved_ip,
                self.deps.repeats,
                self.deps.parallel_repeats,
                "wssize:wsize=1:scale=6",
                protocol,
                settle_max,
                None,
                self.deps.repeats_mode,
                self.deps.quick_break,
                resolved_ips=ip_lists,
            )
        return data

    def _log_batch(self, ctx: BatchContext, ns_name: str, result: BatchProbeResult) -> None:
        fill = f" fill={result.batch_fill_ratio:.0%}"
        log.info(
            "%s",
            f"  {CYAN}[batch] id={ctx.batch_id} ns={ns_name} n={len(ctx.items)} "
            f"settle={result.settle_ms:.0f}ms wall={result.batch_wall_ms:.0f}ms "
            f"backend={result.backend}{fill}{RESET}",
        )


def _bridge_silent(data: dict) -> bool:
    """True when a lua-bridge probe produced no bridge activity at all.

    A live scan_pick emits APPLIED for every tls_client_hello/http_req/
    quic_initial it dissects, so an empty event set means the daemon never
    saw the flow — i.e. nfqws2 is dead and traffic ran queue-bypassed.
    """
    if data.get("bridge_applied"):
        return False
    if data.get("bridge_events") or data.get("bridge_rst_in"):
        return False
    return "bridge_applied" in data  # absent key = non-bridge path (classic)


_FANOUT_BRIDGE_WARNED = False


def warn_fanout_bridge_once() -> None:
    """Fan-out waves use classic per-strategy nfqws2 (bridge incompatible)."""
    global _FANOUT_BRIDGE_WARNED
    if _FANOUT_BRIDGE_WARNED:
        return
    _FANOUT_BRIDGE_WARNED = True
    log.warning(
        "%s",
        f"  {YELLOW}WARN: --lua-bridge ignored for fan-out waves "
        f"(classic per-strategy nfqws2){RESET}",
    )


__all__ = [
    "ProbeBatchService",
    "warn_fanout_bridge_once",
]
