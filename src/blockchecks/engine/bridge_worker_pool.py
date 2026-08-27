"""Shared lua-bridge worker pool: domain isolation and batch flush."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.results import TcpTestResult, campaign_pass
from blockchecks.service.batch_service import STOPPED_BEFORE_PROBE

log = logging.getLogger(__name__)


def result_campaign_pass(result: Any) -> bool:
    """TcpTestResult.campaign_pass(); tests may yield SimpleNamespace(success=...)."""
    fn = getattr(result, "campaign_pass", None)
    if callable(fn):
        return bool(fn())
    return campaign_pass(
        http_ok=bool(getattr(result, "success", False)),
        bridge_applied=getattr(result, "bridge_applied", None),
    )


@dataclass(frozen=True, slots=True)
class BridgeJob:
    """One strategy×domain probe unit for bridge batching."""

    item: StrategyItem
    domain: str
    fanout: bool = False


ProgressHook = Callable[[], Awaitable[None] | None]
AccountOkCb = Callable[..., Awaitable[None]]
AccountSkippedCb = Callable[[BridgeJob], Awaitable[None]]


async def _invoke_progress(on_progress: ProgressHook | None) -> None:
    if on_progress is None:
        return
    outcome = on_progress()
    if outcome is not None:
        await outcome


class DomainIsolationPool:
    """Parallel workers never hold the same domain in-flight when enabled."""

    __slots__ = ("enabled", "active_domains", "domain_lock")

    def __init__(
        self,
        *,
        enabled: bool = True,
        active_domains: set[str] | None = None,
        domain_lock: asyncio.Lock | None = None,
    ) -> None:
        self.enabled = enabled
        self.active_domains = active_domains if active_domains is not None else set()
        self.domain_lock = domain_lock or asyncio.Lock()

    async def claim_domain(self, domain: str) -> bool:
        """Reserve *domain* for this worker's in-flight batch."""
        if not self.enabled:
            return True
        async with self.domain_lock:
            if domain in self.active_domains:
                return False
            self.active_domains.add(domain)
            return True

    async def release_domains(self, domains: Iterable[str]) -> None:
        if not self.enabled or not domains:
            return
        async with self.domain_lock:
            self.active_domains.difference_update(domains)

    async def excluded_snapshot(self, extra: set[str] | None = None) -> set[str]:
        """Domains unavailable for new claims (active + optional extras)."""
        async with self.domain_lock:
            out = set(self.active_domains)
        if extra:
            out |= extra
        return out


async def run_bridge_batch(
    runner: Any,
    jobs: Sequence[BridgeJob],
    *,
    timeout: float,
    stop_event: asyncio.Event | None,
    isolation: DomainIsolationPool | None,
    account_ok: AccountOkCb,
    account_skipped: AccountSkippedCb,
    on_progress: ProgressHook | None = None,
) -> None:
    """Probe a batch via ``runner._run_probe_batch`` with strict result pairing."""
    if not jobs:
        return
    items = [j.item for j in jobs]
    domains = [j.domain for j in jobs]
    try:
        results = list(
            await runner._run_probe_batch(
                items,
                domains[0],
                timeout,
                "lua_bridge",
                domains=domains,
                stop_event=stop_event,
            )
        )
        while len(results) < len(jobs):
            tail = jobs[len(results)]
            results.append(
                TcpTestResult(
                    item=tail.item,
                    domain=tail.domain,
                    success=False,
                    error=STOPPED_BEFORE_PROBE,
                )
            )
        for job, result in zip(jobs, results, strict=True):
            if getattr(result, "error", "") == STOPPED_BEFORE_PROBE:
                await account_skipped(job)
            else:
                await account_ok(job, result_campaign_pass(result), result)
        await _invoke_progress(on_progress)
    finally:
        if isolation is not None:
            await isolation.release_domains(domains)


async def persist_quarantine(runner: Any, quarantine: Any, domain: str) -> None:
    """Persist + notify one newly quarantined domain (best-effort)."""
    info = quarantine.quarantined.get(domain) or {}
    db = getattr(runner, "db", None)
    if db is not None:
        try:
            await db.quarantine_domain(
                domain,
                reason=info.get("reason", ""),
                failed=info.get("attempts", 0),
            )
        except Exception as exc:
            log.warning("%s", f"  [quarantine] DB persist skipped for {domain} ({exc})")
    if quarantine.config.auto_denylist:
        from blockchecks.engine.domain_quarantine import append_denylist

        append_denylist([info])


async def record_quarantine_hit(
    runner: Any,
    quarantine: Any,
    domain: str,
    ok: bool,
    *,
    excluded_domains: set[str] | None,
    fail_phase: str = "",
    error: str = "",
) -> None:
    """Record probe outcome; hard-exclude newly quarantined domains immediately."""
    newly = quarantine.record(
        domain, ok, fail_phase=fail_phase, error=error
    )
    if not newly:
        return
    if excluded_domains is not None:
        excluded_domains.add(newly)
    await persist_quarantine(runner, quarantine, newly)


class BridgeWorkerPool:
    """Shared isolation state for N parallel lua-bridge workers."""

    __slots__ = ("isolation", "runner", "timeout", "stop_event", "quarantine", "excluded_domains")

    def __init__(
        self,
        runner: Any,
        *,
        timeout: float,
        stop_event: asyncio.Event | None = None,
        isolate: bool = True,
        active_domains: set[str] | None = None,
        domain_lock: asyncio.Lock | None = None,
        quarantine: Any = None,
        excluded_domains: set[str] | None = None,
    ) -> None:
        self.runner = runner
        self.timeout = timeout
        self.stop_event = stop_event
        self.quarantine = quarantine
        self.excluded_domains = excluded_domains
        self.isolation = DomainIsolationPool(
            enabled=isolate,
            active_domains=active_domains,
            domain_lock=domain_lock,
        )

    async def flush_batch(
        self,
        jobs: Sequence[BridgeJob],
        *,
        account_ok: AccountOkCb,
        account_skipped: AccountSkippedCb,
        on_progress: ProgressHook | None = None,
    ) -> None:
        await run_bridge_batch(
            self.runner,
            jobs,
            timeout=self.timeout,
            stop_event=self.stop_event,
            isolation=self.isolation,
            account_ok=account_ok,
            account_skipped=account_skipped,
            on_progress=on_progress,
        )

    async def account_with_quarantine(
        self, job: BridgeJob, ok: bool, result: Any = None
    ) -> None:
        if self.quarantine is None:
            return
        await record_quarantine_hit(
            self.runner,
            self.quarantine,
            job.domain,
            ok,
            excluded_domains=self.excluded_domains,
            fail_phase=getattr(result, "fail_phase", "") or "",
            error=getattr(result, "error", "") or "",
        )


async def run_queue_bridge_worker(
    pool: BridgeWorkerPool,
    queue: asyncio.Queue,
    *,
    batch_size: int,
    excluded_domains: set[str],
    account_ok: AccountOkCb,
    account_skipped: AccountSkippedCb,
    on_progress: ProgressHook,
) -> None:
    """Fixed-queue bridge worker (sequential-bridge path adapter)."""
    acc: list[tuple[StrategyItem, str]] = []
    stop_event = pool.stop_event
    isolate = pool.isolation.enabled

    async def flush() -> None:
        nonlocal acc
        if not acc:
            return
        batch = [BridgeJob(item=item, domain=dom) for item, dom in acc]
        acc = []
        await pool.flush_batch(
            batch,
            account_ok=account_ok,
            account_skipped=account_skipped,
            on_progress=lambda: None,
        )
        await _invoke_progress(on_progress)

    while True:
        if stop_event and stop_event.is_set():
            await flush()
            return
        try:
            item, dom = queue.get_nowait()
        except asyncio.QueueEmpty:
            await flush()
            return
        if dom in excluded_domains:
            await account_skipped(BridgeJob(item=item, domain=dom))
            await _invoke_progress(on_progress)
            continue
        if isolate and not await pool.isolation.claim_domain(dom):
            queue.put_nowait((item, dom))
            await asyncio.sleep(0.05)
            await flush()
            continue
        acc.append((item, dom))
        if len(acc) >= batch_size:
            await flush()
