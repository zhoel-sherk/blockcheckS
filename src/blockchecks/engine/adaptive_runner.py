"""AQ5–AQ6: adaptive TCP scan loop (integrates AdaptiveJobQueue + B2 fan-out)."""

from __future__ import annotations

import asyncio
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
from blockchecks.engine.store import RunStateStore
from blockchecks.service.batch_scheduler import BatchJobAccumulator

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
) -> tuple[AdaptiveJobQueue, int]:
    """Create queue, optionally loading persisted weights and applying resume skip."""
    weights = ScanWeights()
    if load_weights and db is not None:
        rows = await db.load_scan_weights()
        if rows:
            weights = ScanWeights.from_rows(rows)

    if provider_store is not None:
        await _apply_provider_weights(provider_store, weights, domains)

    queue = AdaptiveJobQueue.build(items, domains, weights=weights, epsilon=epsilon)
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
    except Exception:
        rows = []
    if not rows:
        return

    domain_set = {d.lower() for d in domains}
    from blockchecks.engine.adaptive_queue import (
        cluster_domain,
        extract_blob_hints,
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
        cl = cluster_domain(dom) if dom else ""
        weights.boost_pass(fam, blobs, cl)
        boosted += 1
    if boosted:
        print(f"  [AQ] provider-preflight: boosted {boosted} approved strategies")


async def run_adaptive_tcp_bridge(
    runner,
    queue: AdaptiveJobQueue,
    *,
    timeout: float = 5.0,
    bridge_batch: int = 500,
    stop_event: asyncio.Event | None = None,
    on_progress: ProgressCb | None = None,
    workers: int = 4,
) -> AdaptiveRunResult:
    """AQ bridge mode: N concurrent accumulators → ProbeBatchService batch flush.

    Each worker accumulates jobs (cross-domain; the bridge is domain-agnostic)
    and flushes up to ``bridge_batch`` jobs per netns, so the whole netns pool is
    used in parallel instead of one serial batch at a time.
    """
    stats = _RunStats()
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


async def _bridge_worker(
    runner,
    queue: AdaptiveJobQueue,
    stats: _RunStats,
    *,
    timeout: float,
    bridge_batch: int,
    stop_event: asyncio.Event | None,
    on_progress: ProgressCb | None,
) -> None:
    acc = BatchJobAccumulator(bridge_batch)

    async def flush() -> None:
        nonlocal acc
        jobs = acc.flush()
        if not jobs:
            return
        items = [j.item for j in jobs]
        domains = [j.domain for j in jobs]
        results = await runner._run_probe_batch(
            items, domains[0], timeout, "lua_bridge", domains=domains
        )
        for job, result in zip(jobs, results, strict=False):
            ok = bool(result.success)
            queue.mark_done(job, passed=ok)
            stats.done += 1
            if ok:
                stats.passed += 1
            if on_progress:
                on_progress(stats.done, stats.skipped, stats.passed)

    async def run_single(job: AdaptiveJob) -> None:
        results = [await runner.test_tcp(job.item, job.domain, timeout=timeout)]
        for result in results:
            ok = bool(result.success)
            queue.mark_done(job, passed=ok)
            stats.done += 1
            if ok:
                stats.passed += 1
            if on_progress:
                on_progress(stats.done, stats.skipped, stats.passed)

    while True:
        if stop_event and stop_event.is_set():
            await flush()
            return
        job = queue.pop()
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
) -> AdaptiveRunResult:
    """Run TCP jobs from *queue* until empty or stopped (AQ5)."""
    if lua_bridge:
        return await run_adaptive_tcp_bridge(
            runner,
            queue,
            timeout=timeout,
            bridge_batch=bridge_batch,
            stop_event=stop_event,
            on_progress=on_progress,
            workers=workers,
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

        item = batch[0].item
        doms = [j.domain for j in batch]

        if len(doms) == 1:
            results = [await runner.test_tcp(item, doms[0], timeout=timeout)]
        else:
            results = await runner.test_tcp_domains(
                item,
                doms,
                timeout=timeout,
                curl_parallel=len(doms),
            )

        for job, result in zip(batch, results):
            ok = bool(result.success)
            queue.mark_done(job, passed=ok)
            done += 1
            if ok:
                passed += 1
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


async def persist_adaptive_weights(db: RunStateStore, weights: ScanWeights) -> None:
    rows = weights.to_rows()
    if rows:
        await db.save_scan_weights(rows)
