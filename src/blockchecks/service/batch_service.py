"""ProbeBatchService — boot batch → probe ×N → shutdown (classic | lua_bridge)."""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

from colorama import Fore, Style

if TYPE_CHECKING:
    pass

from blockchecks.service.batch_bridge_probe import run_tcp_check_bridge
from blockchecks.service.batch_models import (
    BatchContext,
    BatchProbeConfig,
    BatchProbeResult,
    RunnerProbeDeps,
)
from blockchecks.service.batch_scheduler import BatchScheduler
from blockchecks.service.lua_bridge_ipc import LuaBridge
from blockchecks.service.lua_netns import NetnsGoneError, _netns_tcp_probe_cleanup
from blockchecks.service.lua_session import BridgeSession, strategy_text_from_item

CYAN = Fore.CYAN + Style.BRIGHT
RESET = Style.RESET_ALL


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

    async def run_batch(self, ctx: BatchContext, timeout: float) -> BatchProbeResult:
        ns = await self.deps.acquire_ns()
        try:
            domains = ctx.item_domains()
            resolved_by_domain: dict[str, tuple[str | None, str, str]] = {}
            for d in dict.fromkeys(domains):
                resolved_by_domain[d] = await self.deps.resolve_domain_dns(d)
            wall_start = time.monotonic()
            try:
                result = await asyncio.to_thread(
                    self._run_batch_sync,
                    ctx,
                    timeout,
                    ns,
                    resolved_by_domain,
                )
            except NetnsGoneError as e:
                failed = self._batch_fail_results(ctx, str(e))
                result = BatchProbeResult(
                    results=failed,
                    settle_ms=0,
                    backend="lua_bridge",
                    batch_wall_ms=(time.monotonic() - wall_start) * 1000,
                    batch_fill_ratio=0,
                )
                return result
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

    def _run_batch_sync(
        self,
        ctx: BatchContext,
        timeout: float,
        ns_name: str,
        resolved_by_domain: dict[str, tuple[str | None, str, str]],
    ) -> BatchProbeResult:
        if self.config.backend == "lua_bridge":
            return self._run_lua_bridge_batch(ctx, timeout, ns_name, resolved_by_domain)
        return self._run_classic_batch(ctx, timeout, ns_name, resolved_by_domain)

    def _run_classic_batch(
        self,
        ctx: BatchContext,
        timeout: float,
        ns_name: str,
        resolved_by_domain: dict[str, tuple[str | None, str, str]],
    ) -> BatchProbeResult:
        results: list = []
        for item, dom in zip(ctx.items, ctx.item_domains(), strict=False):
            timeout_i, settle_max = self.deps.timing_for(item, timeout)
            protocol = getattr(item, "protocol", ctx.protocol) or ctx.protocol
            resolved_ip, _, _ = resolved_by_domain[dom]
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
            )
            data = self._maybe_wssize_retry(
                item, ctx, timeout_i, ns_name, resolved_ip, protocol, settle_max, data
            )
            data["batch_id"] = ctx.batch_id
            result = self.deps.tcp_result_from_data(item, dom, data)
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
            self._record_daemon_mem(ns_name)
            for idx, (item, dom) in enumerate(
                zip(ctx.items, ctx.item_domains(), strict=False), start=1
            ):
                if self._maybe_recycle(ns_name, session):
                    recycled += 1
                gen = self.deps.next_probe_gen()
                timeout_i, _ = self.deps.timing_for(item, timeout)
                item_proto = getattr(item, "protocol", protocol) or protocol
                resolved_ip, _, _ = resolved_by_domain[dom]
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
                )
                data = self._maybe_wssize_bridge_retry(
                    session, idx, item, ctx, timeout_i, resolved_ip, item_proto, data, domain=dom
                )
                data["batch_id"] = ctx.batch_id
                result = self.deps.tcp_result_from_data(item, dom, data)
                results.append(result)
        finally:
            session.shutdown()
        return BatchProbeResult(
            results=results,
            settle_ms=settle_ms,
            backend="lua_bridge",
        )

    def _record_daemon_mem(self, ns_name: str) -> None:
        if self.memory_monitor is None or self.config.backend != "lua_bridge":
            return
        if not self.memory_monitor.should_sample():
            return
        self.memory_monitor.record_ns(ns_name)
        if self.memory_monitor.worker_over_limit():
            print(
                f"  {Fore.YELLOW}[mem] python worker RSS over threshold "
                f"(see BLOCKCHECKS_MEM_PY_MAX_MIB){Style.RESET_ALL}"
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
            print(
                f"  {Fore.YELLOW}[mem] recycle nfqws2 pid={pid} ({reason}) "
                f"in {ns_name}{Style.RESET_ALL}"
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
    ) -> dict:
        if (
            not data.get("success")
            and self.deps.try_wssize
            and protocol == "tls12"
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
            )
        return data

    def _maybe_wssize_bridge_retry(
        self,
        session: BridgeSession,
        idx: int,
        item,
        ctx: BatchContext,
        timeout_i: float,
        resolved_ip: str | None,
        protocol: str,
        data: dict,
        *,
        domain: str | None = None,
    ) -> dict:
        if (
            not data.get("success")
            and self.deps.try_wssize
            and protocol == "tls12"
            and "wssize" not in item.strategy
        ):
            gen = self.deps.next_probe_gen()
            return run_tcp_check_bridge(
                session,
                idx,
                gen,
                item.strategy,
                domain or ctx.domain,
                timeout_i,
                self.deps.python,
                self.deps.disable_ech,
                resolved_ip,
                self.deps.repeats,
                self.deps.parallel_repeats,
                "wssize:wsize=1:scale=6",
                protocol,
                self.deps.repeats_mode,
                self.deps.quick_break,
            )
        return data

    def _log_batch(self, ctx: BatchContext, ns_name: str, result: BatchProbeResult) -> None:
        fill = f" fill={result.batch_fill_ratio:.0%}"
        print(
            f"  {CYAN}[batch] id={ctx.batch_id} ns={ns_name} n={len(ctx.items)} "
            f"settle={result.settle_ms:.0f}ms wall={result.batch_wall_ms:.0f}ms "
            f"backend={result.backend}{fill}{RESET}"
        )


_FANOUT_BRIDGE_WARNED = False


def warn_fanout_bridge_once() -> None:
    """Fan-out waves use classic per-strategy nfqws2 (bridge incompatible)."""
    global _FANOUT_BRIDGE_WARNED
    if _FANOUT_BRIDGE_WARNED:
        return
    _FANOUT_BRIDGE_WARNED = True
    yellow = Fore.YELLOW
    print(
        f"  {yellow}WARN: --lua-bridge ignored for fan-out waves "
        f"(classic per-strategy nfqws2){RESET}"
    )


__all__ = [
    "ProbeBatchService",
    "warn_fanout_bridge_once",
]
