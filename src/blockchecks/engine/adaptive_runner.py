"""TCP scan loop driven by AdaptiveJobQueue."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from blockchecks.engine.adaptive_queue import (
    AdaptiveJob,
    AdaptiveJobQueue,
    AdaptiveMetrics,
    ScanWeights,
)
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.results import TcpTestResult
from blockchecks.engine.store import RunStateStore
from blockchecks.service.batch_scheduler import BatchJobAccumulator
from blockchecks.service.batch_service import STOPPED_BEFORE_PROBE

log = logging.getLogger(__name__)


ProgressCb = Callable[[int, int, int], None]
ResumeCb = Callable[[AdaptiveJob], Awaitable[bool]]


@dataclass
class AdaptiveRunResult:
    done: int
    skipped: int
    passed: int
    metrics: AdaptiveMetrics
    weights: ScanWeights


async def build_adaptive_queue(
    items: list[StrategyItem],
    domains: list[str],
    db: RunStateStore | None,
    *,
    epsilon: float = 0.1,
    load_weights: bool = True,
    resume_check: ResumeCb | None = None,
    provider_store: Any = None,
    triage: Any = None,
    quarantine=None,
) -> tuple[AdaptiveJobQueue, int]:
    """Create queue, optionally loading persisted weights and applying resume skip."""
    weights = ScanWeights()
    if load_weights and db is not None:
        rows = await db.load_scan_weights()
        if rows:
            weights = ScanWeights.from_rows(rows)

    if provider_store is not None:
        await _apply_provider_weights(provider_store, weights, domains)

    if triage is not None:
        weights.seed_from_triage(triage)

    queue = AdaptiveJobQueue.build(items, domains, weights=weights, epsilon=epsilon)
    if quarantine is not None:
        # Hard-exclude quarantined domains BEFORE resume filtering so dead
        # domains never enter the heap at all.
        queue.excluded_domains |= quarantine.exclude_domains()
    skipped = 0
    if resume_check:
        skipped = await queue.filter_resume(resume_check)
    return queue, skipped


async def _apply_provider_weights(
    provider_store: Any,
    weights: ScanWeights,
    domains: list[str],
) -> None:
    """Boost AQ weights for strategies the provider already saw passing.

    Reads ``data_block`` pass_strategies and raises family/blob/cluster weights
    for approved PASS strategies on the scanned domains — so the adaptive scan
    tests the most promising candidates first (provider-result orchestration).
    """
    try:
        if hasattr(provider_store, "pass_strategies"):
            rows = await provider_store.pass_strategies(approved_only=True)
        else:
            rows = []
    except Exception as exc:
        log.warning("%s", f"  WARNING: provider pass_strategies load failed ({exc})")
        rows = []
    if not rows:
        return

    domain_set = {d.lower() for d in domains}
    from blockchecks.engine.adaptive_queue import (
        extract_blob_hints,
        strategy_traits,
    )
    from blockchecks.engine.family_needs import classify_strategy_family
    from blockchecks.engine.generators.base import StrategyItem

    boosted = 0
    for row in rows:
        dom = (row.get("domain") or "").lower()
        if dom and dom not in domain_set:
            continue
        strat = row.get("strategy") or ""
        if not strat:
            continue
        item = StrategyItem(label=strat, strategy=strat)
        fam = classify_strategy_family(item)
        blobs = extract_blob_hints(strat)
        traits = strategy_traits(strat)
        if weights.boost_provider_once(strat, fam, blobs, traits):
            boosted += 1
    if boosted:
        log.info("%s", f"  [AQ] provider-preflight: boosted {boosted} approved strategies")


async def run_adaptive_tcp_bridge(
    runner,
    queue: AdaptiveJobQueue,
    *,
    timeout: float = 5.0,
    bridge_batch: int = 500,
    stop_event: asyncio.Event | None = None,
    on_progress: ProgressCb | None = None,
    workers: int = 4,
    quarantine=None,
) -> AdaptiveRunResult:
    """AQ bridge mode: N concurrent accumulators → ProbeBatchService batch flush.

    Each worker accumulates jobs (cross-domain; the bridge is domain-agnostic)
    and flushes up to ``bridge_batch`` jobs per netns, so the whole netns pool is
    used in parallel instead of one serial batch at a time.

    Workers share an *active_domains* set so the pool always probes distinct
    domains simultaneously (domain isolation — no all-youtube false positives).
    """
    stats = _RunStats()
    from blockchecks.engine.config import AQ_DOMAIN_ISOLATE

    active_domains: set[str] = set()
    if quarantine is not None:
        active_domains |= quarantine.exclude_domains()
    domain_lock = asyncio.Lock()
    tasks = [
        asyncio.create_task(
            _bridge_worker(
                runner,
                queue,
                stats,
                timeout=timeout,
                bridge_batch=bridge_batch,
                stop_event=stop_event,
                on_progress=on_progress,
                active_domains=active_domains if AQ_DOMAIN_ISOLATE else None,
                domain_lock=domain_lock if AQ_DOMAIN_ISOLATE else None,
                quarantine=quarantine,
            )
        )
        for _ in range(max(1, int(workers)))
    ]
    await asyncio.gather(*tasks)

    return AdaptiveRunResult(
        done=stats.done,
        skipped=stats.skipped,
        passed=stats.passed,
        metrics=queue.metrics,
        weights=queue.weights,
    )


class _RunStats:
    """Mutable shared counters updated between awaits (event-loop thread only)."""

    __slots__ = ("done", "skipped", "passed")

    def __init__(self) -> None:
        self.done = 0
        self.skipped = 0
        self.passed = 0


async def _bridge_worker(  # noqa: C901
    runner,
    queue: AdaptiveJobQueue,
    stats: _RunStats,
    *,
    timeout: float,
    bridge_batch: int,
    stop_event: asyncio.Event | None,
    on_progress: ProgressCb | None,
    active_domains: set[str] | None = None,
    domain_lock: asyncio.Lock | None = None,
    quarantine=None,
) -> None:
    """One AQ bridge worker.

    Domain isolation: workers share *active_domains* (+ lock). Each worker
    pops jobs whose domain is not already probed by another worker, so with
    ``parallel=N`` netns we always test N distinct domains simultaneously —
    never all-youtube. The domain is released when the accumulated batch is
    flushed (or a single fanout job runs).
    """
    acc = BatchJobAccumulator(bridge_batch)
    queue.configure_heap_rebuild(bridge_batch)
    active_domains = active_domains or set()
    domain_lock = domain_lock or asyncio.Lock()

    async def _account(job: AdaptiveJob, ok: bool) -> None:
        queue.mark_done(job, passed=ok)
        stats.done += 1
        if ok:
            stats.passed += 1
        if quarantine is not None:
            newly = quarantine.record(job.domain, ok)
            if newly:
                # Hard-exclude immediately so sibling workers drop these jobs.
                queue.excluded_domains.add(domain := newly)
                await _persist_quarantine(runner, quarantine, domain)

    async def _account_skipped(job: AdaptiveJob) -> None:
        queue.mark_done(job, passed=False)
        stats.skipped += 1
        stats.done += 1

    async def flush() -> None:
        nonlocal acc
        jobs = acc.flush()
        if not jobs:
            return
        items = [j.item for j in jobs]
        domains = [j.domain for j in jobs]
        results = list(
            await runner._run_probe_batch(
                items, domains[0], timeout, "lua_bridge", domains=domains, stop_event=stop_event
            )
        )
        while len(results) < len(jobs):
            job = jobs[len(results)]
            results.append(
                TcpTestResult(
                    item=job.item,
                    domain=job.domain,
                    success=False,
                    error=STOPPED_BEFORE_PROBE,
                )
            )
        for job, result in zip(jobs, results, strict=True):
            if result.error == STOPPED_BEFORE_PROBE:
                await _account_skipped(job)
                if on_progress:
                    on_progress(stats.done, stats.skipped, stats.passed)
                continue
            ok = bool(result.success)
            await _account(job, ok)
            if on_progress:
                on_progress(stats.done, stats.skipped, stats.passed)
        async with domain_lock:
            active_domains.difference_update(domains)

    async def pop_isolated() -> AdaptiveJob | None:
        """Pop a job whose domain is not currently probed by another worker."""
        async with domain_lock:
            exclude = set(active_domains)
            if quarantine is not None:
                exclude |= quarantine.exclude_domains()
            job = queue.pop(exclude_domains=exclude)
            if job is not None:
                active_domains.add(job.domain)
            return job

    async def run_single(job: AdaptiveJob) -> None:
        results = [await runner.test_tcp(job.item, job.domain, timeout=timeout)]
        for result in results:
            ok = bool(result.success)
            await _account(job, ok)
            if on_progress:
                on_progress(stats.done, stats.skipped, stats.passed)
        async with domain_lock:
            active_domains.discard(job.domain)

    while True:
        if stop_event and stop_event.is_set():
            await flush()
            return
        job = await pop_isolated()
        if job is None:
            await flush()
            return

        if job.fanout:
            await flush()
            await run_single(job)
            if stop_event and stop_event.is_set():
                return
            continue

        if not acc.push(job):
            await flush()
            if not acc.push(job):
                await run_single(job)
                if stop_event and stop_event.is_set():
                    return
                continue

        # Incremental progress even before the batch flush: report completed
        # (stats.done) plus jobs currently accumulated in this worker's batch,
        # so a long run with bridge_batch=500 doesn't show a frozen [0/N].
        if on_progress:
            on_progress(stats.done + len(acc), stats.skipped, stats.passed)

        if acc.is_full():
            await flush()

        if stop_event and stop_event.is_set():
            return


async def run_adaptive_tcp(
    runner,
    queue: AdaptiveJobQueue,
    *,
    timeout: float = 5.0,
    curl_parallel: int = 1,
    protocol: str = "tls12",
    disable_ech: bool = False,
    stop_event: asyncio.Event | None = None,
    on_progress: ProgressCb | None = None,
    lua_bridge: bool = False,
    bridge_batch: int = 500,
    workers: int = 4,
    quarantine=None,
) -> AdaptiveRunResult:
    """Run TCP jobs from *queue* until empty or stopped (AQ5)."""
    backend = "lua_bridge" if lua_bridge else "classic"
    log.info("%s", f"  AQ backend={backend}")
    if lua_bridge:
        return await run_adaptive_tcp_bridge(
            runner,
            queue,
            timeout=timeout,
            bridge_batch=bridge_batch,
            stop_event=stop_event,
            on_progress=on_progress,
            workers=workers,
            quarantine=quarantine,
        )

    done = 0
    skipped = 0
    passed = 0
    batch_size = max(1, int(curl_parallel))

    while True:
        if stop_event and stop_event.is_set():
            break
        batch = queue.pop_batch(
            batch_size,
            protocol=protocol,
            disable_ech=disable_ech,
        )
        if not batch:
            break

        if quarantine is not None:
            dead = quarantine.exclude_domains()
            if dead:
                quarantined_jobs = [j for j in batch if j.domain in dead]
                batch = [j for j in batch if j.domain not in dead]
                for job in quarantined_jobs:
                    queue.mark_done(job, passed=False)
                    skipped += 1
                    done += 1
                if not batch:
                    continue

        item = batch[0].item
        doms = [j.domain for j in batch]
        results = await _classic_aq_probe(runner, item, doms, timeout)

        for job, result in zip(batch, results):
            ok = bool(result.success)
            queue.mark_done(job, passed=ok)
            done += 1
            if ok:
                passed += 1
            if quarantine is not None:
                newly = quarantine.record(job.domain, ok)
                if newly:
                    await _persist_quarantine(runner, quarantine, newly)
            if on_progress:
                on_progress(done, skipped, passed)
            if stop_event and stop_event.is_set():
                break

        if stop_event and stop_event.is_set():
            break

    return AdaptiveRunResult(
        done=done,
        skipped=skipped,
        passed=passed,
        metrics=queue.metrics,
        weights=queue.weights,
    )


async def _classic_aq_probe(runner, item, doms: list[str], timeout: float):
    """One classic AQ pop: ProbeBatchService for a single domain, B2 otherwise."""
    if len(doms) == 1:
        return await runner._run_probe_batch([item], doms[0], timeout, "classic")
    log.info("%s", f"  [AQ] backend=classic n={len(doms)}")
    return await runner.test_tcp_domains(
        item, doms, timeout=timeout, curl_parallel=len(doms)
    )


async def _persist_quarantine(runner, quarantine, domain: str) -> None:
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


async def persist_adaptive_weights(db: RunStateStore, weights: ScanWeights) -> None:
    rows = weights.to_rows()
    if rows:
        await db.save_scan_weights(rows)
