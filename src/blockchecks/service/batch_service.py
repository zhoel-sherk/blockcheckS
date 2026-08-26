"""Boot a batch, probe each item, shut down. Backends: classic or lua_bridge."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

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

STOPPED_BEFORE_PROBE = "stopped before probe"
NS_POOL_EXHAUSTED = "ns pool exhausted"
PROBE_SKIP_ERRORS = frozenset({STOPPED_BEFORE_PROBE, NS_POOL_EXHAUSTED})

_pool_exhausted_total = 0


def pool_exhausted_total() -> int:
    """Cumulative netns pool acquire timeouts (for triage/metrics)."""
    return _pool_exhausted_total


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
            return await self._finalize_batch(ctx, self._empty_stopped_result(ctx))
        # Bound the acquisition: if every netns is busy (e.g. a hung batch holds
        # the pool), wait_for lets us bail out instead of deadlocking the stop.
        try:
            ns = await asyncio.wait_for(self.deps.acquire_ns(), timeout=ACQUIRE_NS_TIMEOUT)
        except TimeoutError:
            global _pool_exhausted_total
            _pool_exhausted_total += 1
            log.warning(
                "netns pool exhausted after %.1fs (batch_id=%s, total=%d)",
                ACQUIRE_NS_TIMEOUT,
                ctx.batch_id,
                _pool_exhausted_total,
            )
            return await self._finalize_batch(ctx, self._pool_exhausted_result(ctx))
        try:
            domains = ctx.item_domains()
            resolved_by_domain: dict[str, tuple[str | None, str, str]] = {}
            ip_lists_by_domain: dict[str, list[str]] = {}
            for d in dict.fromkeys(domains):
                resolved_by_domain[d] = await self.deps.resolve_domain_dns(d)
                ip_lists_by_domain[d] = self.deps.resolve_domain_ips(d)
            if stop_event is not None and stop_event.is_set():
                return await self._finalize_batch(
                    ctx, self._empty_stopped_result(ctx), resolved_by_domain
                )
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
            return await self._finalize_batch(ctx, result, resolved_by_domain, ns=ns)
        finally:
            await self.deps.release_ns(ns)

    async def _finalize_batch(
        self,
        ctx: BatchContext,
        result: BatchProbeResult,
        resolved_by_domain: dict[str, tuple[str | None, str, str]] | None = None,
        *,
        ns: str | None = None,
    ) -> BatchProbeResult:
        domains = ctx.item_domains()
        result.results = self._pad_unprobed_results(ctx, result.results)
        empty_dns: tuple[str | None, str, str] = (None, "", "")
        for item, dom, probe_result in zip(ctx.items, domains, result.results, strict=True):
            resolved_ip, dns_verdict, doh_server = (resolved_by_domain or {}).get(
                dom, empty_dns
            )
            await self.deps.log_tcp_result(
                item,
                dom,
                probe_result,
                resolved_ip=resolved_ip,
                dns_verdict=dns_verdict,
                doh_server=doh_server,
            )
        if ns is not None:
            self._log_batch(ctx, ns, result)
        return result

    @staticmethod
    def _empty_stopped_result(ctx: BatchContext) -> BatchProbeResult:
        """Empty result when a stop was requested before the batch started."""
        return ProbeBatchService._skipped_batch_result(ctx, STOPPED_BEFORE_PROBE)

    @staticmethod
    def _pool_exhausted_result(ctx: BatchContext) -> BatchProbeResult:
        """Empty result when no netns could be acquired within the pool timeout."""
        return ProbeBatchService._skipped_batch_result(ctx, NS_POOL_EXHAUSTED)

    @staticmethod
    def _skipped_batch_result(ctx: BatchContext, error: str) -> BatchProbeResult:
        from blockchecks.engine.results import TcpTestResult

        results = [
            TcpTestResult(
                item=item,
                domain=dom,
                success=False,
                error=error,
            )
            for item, dom in zip(ctx.items, ctx.item_domains(), strict=True)
        ]
        return BatchProbeResult(
            results=results,
            settle_ms=0,
            backend="",
            batch_wall_ms=0,
            batch_fill_ratio=0,
        )

    @staticmethod
    def _pad_unprobed_results(ctx: BatchContext, results: list) -> list:
        """Append SKIPPED placeholders for batch tail aborted by stop_event."""
        from blockchecks.engine.results import TcpTestResult

        domains = ctx.item_domains()
        if len(results) >= len(ctx.items):
            return results
        out = list(results)
        for item, dom in zip(ctx.items[len(out) :], domains[len(out) :], strict=True):
            out.append(
                TcpTestResult(
                    item=item,
                    domain=dom,
                    success=False,
                    error=STOPPED_BEFORE_PROBE,
                )
            )
        return out

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
        for item, dom in zip(ctx.items, ctx.item_domains(), strict=True):
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
                    "SKIPPED"
                    if result.error in PROBE_SKIP_ERRORS
                    else (
                        "THROTTLED"
                        if result.throttled
                        else ("PASS" if result.success else "FAIL")
                    )
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
        for item, dom in zip(ctx.items, ctx.item_domains(), strict=True):
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
                zip(ctx.items, ctx.item_domains(), strict=True), start=1
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
                    self._reboot_daemon(session)
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
                    self._reboot_daemon(session)
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
                    self._reboot_daemon(session)
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
                        "SKIPPED"
                        if result.error in PROBE_SKIP_ERRORS
                        else (
                            "THROTTLED"
                            if result.throttled
                            else ("PASS" if result.success else "FAIL")
                        )
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
        except Exception as exc:
            log.warning("daemon heartbeat_age failed: %s", exc)
            return False
        if not isinstance(age, (int, float)):
            return False
        return age > max_age

    def _wait_heartbeat(self, session: BridgeSession, within: float = 1.2) -> bool:
        """Block until the daemon's Lua heartbeat is fresh (age <= 1.0s).

        Proof that the Lua event loop is running and the desync plan is built;
        probing before that risks queue-bypassed clean traffic.
        """
        deadline = time.monotonic() + within
        while time.monotonic() < deadline:
            try:
                age = session.bridge.heartbeat_age()
            except Exception as exc:
                log.debug("wait_heartbeat age failed: %s", exc)
                age = None
            if isinstance(age, (int, float)) and age <= 1.0:
                return True
            time.sleep(0.05)
        return False

    def _bridge_ready_fence(
        self,
        session: BridgeSession,
        ctx: BatchContext,
        timeout: float,
        resolved_by_domain: dict[str, tuple[str | None, str, str]],
    ) -> None:
        """Wait for the daemon's Lua heartbeat right after boot (readiness).

        settle only waits for process visibility (/proc); Lua init (3 scripts
        + plan build) and the NFQUEUE bind can lag behind — early probes then
        leave the netns clean (queue-bypass) producing false "PASS without
        APPLIED" rows. The heartbeat timer (init.lua, 200ms) is a cheap proof
        that the Lua event loop is alive; no synthetic curl needed. On silence
        the daemon reboots once and we wait again; give up with a warning —
        the per-probe zero-event retry remains as the last-resort backstop.
        """
        del ctx, timeout, resolved_by_domain  # readiness no longer probes

        if self._wait_heartbeat(session):
            return
        log.warning(
            "%s",
            f"  {YELLOW}[bridge] no heartbeat from {session.ns_name} within 1.2s "
            f"— rebooting daemon and waiting again{RESET}",
        )
        self._reboot_daemon(session)
        if self._daemon_heartbeat_stale(session):
            log.warning(
                "%s",
                f"  {YELLOW}[bridge] daemon in {session.ns_name} unresponsive to fence — "
                f"probes may run clean (queue-bypass){RESET}",
            )

    def _reboot_daemon(self, session: BridgeSession) -> float:
        """Boot nfqws2 and wait for Lua heartbeat before the next probe."""
        settle = session.boot()
        self._wait_heartbeat(session)
        return settle

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
        self._reboot_daemon(session)
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
        from blockchecks.engine.wssize_retry import WSSIZE_RETRY

        if WSSIZE_RETRY.should_retry(
            data,
            try_wssize=self.deps.try_wssize,
            protocol=protocol,
            strategy=item.strategy,
            is_config=item.is_config,
        ):
            return self.deps.run_tcp_check(
                ns_name,
                item.strategy,
                ctx.domain,
                WSSIZE_RETRY.retry_timeout(timeout_i),
                item.is_config,
                self.deps.python,
                self.deps.disable_ech,
                resolved_ip,
                self.deps.repeats,
                self.deps.parallel_repeats,
                WSSIZE_RETRY.cmd,
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
    "NS_POOL_EXHAUSTED",
    "POOL_ACQUIRE_TIMEOUT",
    "ProbeBatchService",
    "STOPPED_BEFORE_PROBE",
    "pool_exhausted_total",
    "warn_fanout_bridge_once",
]

# Back-compat alias (audit RT-16 renamed marker).
POOL_ACQUIRE_TIMEOUT = NS_POOL_EXHAUSTED
