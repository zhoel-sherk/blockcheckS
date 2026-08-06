"""Batch TCP probing — N strategies per nfqws2 lifecycle (classic or lua_bridge)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

from colorama import Fore, Style

from blockchecks.checkers.curl_probe import (
    CurlProbeRequest,
    is_googlevideo_domain,
    prepare_googlevideo_probe,
    worker_wall_timeout,
)
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.config import DEFAULT_BRIDGE_BATCH_MAX
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.lua_bridge import BridgeSession, LuaBridge, strategy_text_from_item
from blockchecks.engine.lua_bridge import NetnsGoneError, _netns_tcp_probe_cleanup
from blockchecks.engine.probe import invoke_curl_probe_worker, probe_request_dict

CYAN = Fore.CYAN + Style.BRIGHT
RESET = Style.RESET_ALL

ProbeBackend = Literal["classic", "lua_bridge"]


@dataclass(frozen=True)
class BatchContext:
    ns_name: str
    items: list[StrategyItem]
    domain: str
    batch_id: int
    protocol: str = "tls12"
    domains: list[str] | None = None  # parallel to items; defaults to domain

    def item_domains(self) -> list[str]:
        if self.domains is not None and len(self.domains) == len(self.items):
            return list(self.domains)
        return [self.domain] * len(self.items)


@dataclass(frozen=True)
class BatchProbeConfig:
    backend: ProbeBackend
    batch_size: int = 500
    lua_extra: tuple[str, ...] = ()
    compare_classic: bool = False


@dataclass
class BatchProbeResult:
    results: list
    settle_ms: float = 0.0
    batch_wall_ms: float = 0.0
    backend: str = "classic"
    batch_fill_ratio: float = 1.0


@dataclass
class RunnerProbeDeps:
    """Minimal runner contract for ProbeBatchService (avoids cyclic imports)."""

    python: str
    disable_ech: bool
    repeats: int
    parallel_repeats: bool
    repeats_mode: str
    quick_break: bool
    try_wssize: bool
    lua_extra: list[str]
    timing_for: Callable[[StrategyItem, float], tuple[float, float | None]]
    resolve_domain_dns: Callable[[str], Awaitable[tuple[str | None, str, str]]]
    tcp_result_from_data: Callable[[StrategyItem, str, dict], object]
    log_tcp_result: Callable[..., Awaitable[None]]
    next_probe_gen: Callable[[], int]
    run_tcp_check: Callable[..., dict]
    acquire_ns: Callable[[], Awaitable[str]]
    release_ns: Callable[[str], Awaitable[None]]


class BatchScheduler:
    """Chunk strategies/jobs into bridge-sized batches."""

    def __init__(self, batch_size: int) -> None:
        self.batch_size = max(1, min(batch_size, DEFAULT_BRIDGE_BATCH_MAX))

    def iter_batches(self, items: list[StrategyItem]) -> list[list[StrategyItem]]:
        n = self.batch_size
        if not items:
            return []
        return [items[i : i + n] for i in range(0, len(items), n)]

    def group_jobs_by_domain(
        self,
        jobs: list[AdaptiveJob],
        *,
        flush_partial: bool = True,
    ) -> list[list[AdaptiveJob]]:
        """Group consecutive jobs with same domain into batches up to batch_size."""
        if not jobs:
            return []
        out: list[list[AdaptiveJob]] = []
        cur_domain = jobs[0].domain
        cur: list[AdaptiveJob] = []
        labels: set[str] = set()

        for job in jobs:
            if job.domain != cur_domain:
                if cur:
                    out.append(cur)
                cur = []
                labels = set()
                cur_domain = job.domain
            if job.item.label in labels:
                if cur:
                    out.append(cur)
                cur = [job]
                labels = {job.item.label}
                continue
            if len(cur) >= self.batch_size:
                out.append(cur)
                cur = []
                labels = set()
            cur.append(job)
            labels.add(job.item.label)

        if cur and (flush_partial or len(cur) >= self.batch_size):
            out.append(cur)
        return out


class BatchJobAccumulator:
    """AQ bridge mode: accumulate jobs until batch_size unique (label, domain) keys.

    The bridge is domain-agnostic (netns iptables redirects all :443 traffic to
    nfqws2; strategy selected by published id), so jobs from *different* domains
    can share one batch. Only fan-out waves are excluded (classic per-strategy).
    """

    def __init__(self, batch_size: int) -> None:
        self.batch_size = max(1, batch_size)
        self._jobs: list[AdaptiveJob] = []
        self._keys: set[tuple[str, str]] = set()

    def __len__(self) -> int:
        return len(self._jobs)

    @property
    def domain(self) -> str | None:
        return self._jobs[0].domain if self._jobs else None

    @property
    def domains(self) -> list[str]:
        return [j.domain for j in self._jobs]

    def flush(self) -> list[AdaptiveJob]:
        jobs = self._jobs
        self._jobs = []
        self._keys = set()
        return jobs

    def can_accept(self, job: AdaptiveJob) -> bool:
        if job.fanout:
            return False
        if job.key in self._keys:
            return False
        return len(self._jobs) < self.batch_size

    def push(self, job: AdaptiveJob) -> bool:
        if not self.can_accept(job):
            return False
        self._jobs.append(job)
        self._keys.add(job.key)
        return True

    def is_full(self) -> bool:
        return len(self._jobs) >= self.batch_size


def run_tcp_check_bridge(
    session: BridgeSession,
    strategy_id: int,
    gen: int,
    strategy: str,
    domain: str,
    timeout: float,
    python_bin: str,
    disable_ech: bool = False,
    resolved_ip: str | None = None,
    repeats: int = 1,
    parallel_repeats: bool = False,
    extra_lua_desync: str = "",
    protocol: str = "tls12",
    repeats_mode: str = "fast",
    quick_break: bool = False,
) -> dict:
    """Publish strategy id to shm IPC and curl (nfqws2 already running)."""
    is_http = protocol == "http"
    is_gv = not is_http and is_googlevideo_domain(domain)

    if is_gv:
        probe_req, gv_err = prepare_googlevideo_probe(domain, resolved_ip=resolved_ip)
        if gv_err:
            return gv_err
        resolved_ip = probe_req.resolved_ip
    else:
        probe_req = CurlProbeRequest(
            domain=domain,
            timeout=timeout,
            resolved_ip=resolved_ip,
            resolve_name=domain.split("/")[0],
            disable_ech=disable_ech,
            protocol=protocol,
        )

    session.bridge.truncate_events()
    session.bridge.publish(strategy_id, gen, strategy if extra_lua_desync else None)

    probe_req.timeout = timeout
    payload = {
        "mode": "single",
        "request": probe_request_dict(probe_req),
        "repeats": max(1, int(repeats)),
        "parallel_repeats": bool(parallel_repeats and repeats > 1),
        "repeats_mode": repeats_mode,
        "quick_break": bool(quick_break),
    }
    wall = worker_wall_timeout(
        timeout,
        repeats,
        n_domains=1,
        curl_parallel=1,
        parallel_repeats=parallel_repeats,
    )
    data = invoke_curl_probe_worker(session.ns_name, python_bin, payload, wall)
    data["settle_ms"] = 0.0
    data["bridge_gen"] = gen
    data["bridge_id"] = strategy_id
    events = session.bridge.drain_events(since_gen=gen)
    data["bridge_events"] = [e.event for e in events]
    return data


class ProbeBatchService:
    """Boot batch → probe ×N → shutdown with classic or lua_bridge backend."""

    def __init__(self, config: BatchProbeConfig, deps: RunnerProbeDeps) -> None:
        self.config = config
        self.deps = deps
        self.scheduler = BatchScheduler(config.batch_size)

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
        try:
            settle_ms = session.boot() * 1000
            for idx, (item, dom) in enumerate(
                zip(ctx.items, ctx.item_domains(), strict=False), start=1
            ):
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

    def _maybe_wssize_retry(
        self,
        item: StrategyItem,
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
        item: StrategyItem,
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
