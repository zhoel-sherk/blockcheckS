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
from blockchecks.engine.bridge_worker_pool import (
    BridgeJob,
    BridgeWorkerPool,
    persist_quarantine,
)
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.store import RunStateStore
from blockchecks.service.batch_scheduler import BatchJobAccumulator

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
    pool = BridgeWorkerPool(
        runner,
        timeout=timeout,
        stop_event=stop_event,
        isolate=bool(AQ_DOMAIN_ISOLATE),
        active_domains=active_domains,
        quarantine=quarantine,
        excluded_domains=queue.excluded_domains,
    )
    tasks = [
        asyncio.create_task(
            _bridge_worker(
                pool,
                queue,
                stats,
                bridge_batch=bridge_batch,
                on_progress=on_progress,
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
    pool: BridgeWorkerPool,
    queue: AdaptiveJobQueue,
    stats: _RunStats,
    *,
    bridge_batch: int,
    on_progress: ProgressCb | None,
) -> None:
    """One AQ bridge worker (thin adapter over :class:`BridgeWorkerPool`)."""
    acc = BatchJobAccumulator(bridge_batch)
    queue.configure_heap_rebuild(bridge_batch)
    stop_event = pool.stop_event
    quarantine = pool.quarantine

    async def _account(job: AdaptiveJob, ok: bool) -> None:
        queue.mark_done(job, passed=ok)
        stats.done += 1
        if ok:
            stats.passed += 1
        await pool.account_with_quarantine(
            BridgeJob(item=job.item, domain=job.domain, fanout=job.fanout),
            ok,
        )

    async def _account_skipped(job: AdaptiveJob) -> None:
        queue.mark_done(job, passed=False)
        stats.skipped += 1
        stats.done += 1

    def _report_progress() -> None:
        if on_progress:
            on_progress(stats.done, stats.skipped, stats.passed)

    async def flush() -> None:
        nonlocal acc
        aq_jobs = acc.flush()
        if not aq_jobs:
            return
        batch = [BridgeJob(item=j.item, domain=j.domain, fanout=j.fanout) for j in aq_jobs]
        job_by_key = {(j.item.label, j.domain): j for j in aq_jobs}

        async def account_ok(bj: BridgeJob, ok: bool) -> None:
            await _account(job_by_key[(bj.item.label, bj.domain)], ok)

        async def account_skipped_bj(bj: BridgeJob) -> None:
            await _account_skipped(job_by_key[(bj.item.label, bj.domain)])

        await pool.flush_batch(
            batch,
            account_ok=account_ok,
            account_skipped=account_skipped_bj,
            on_progress=_report_progress,
        )

    async def pop_isolated() -> AdaptiveJob | None:
        extra = quarantine.exclude_domains() if quarantine is not None else None
        exclude = await pool.isolation.excluded_snapshot(extra)
        async with pool.isolation.domain_lock:
            job = queue.pop(exclude_domains=exclude)
            if job is not None:
                pool.isolation.active_domains.add(job.domain)
            return job

    async def run_single(job: AdaptiveJob) -> None:
        try:
            result = await pool.runner.test_tcp(job.item, job.domain, timeout=pool.timeout)
            await _account(job, bool(result.success))
            _report_progress()
        finally:
            await pool.isolation.release_domains([job.domain])

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
                    await persist_quarantine(runner, quarantine, newly)
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


async def persist_adaptive_weights(db: RunStateStore, weights: ScanWeights) -> None:
    rows = weights.to_rows()
    if rows:
        await db.save_scan_weights(rows)
