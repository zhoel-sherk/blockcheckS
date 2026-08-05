"""AQ5–AQ6: adaptive TCP scan loop (integrates AdaptiveJobQueue + B2 fan-out)."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from blockchecks.engine.adaptive_queue import (
    AdaptiveJob,
    AdaptiveJobQueue,
    AdaptiveMetrics,
    ScanWeights,
)
from blockchecks.engine.batch_probe import BatchJobAccumulator
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.store import RunStateStore

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
) -> tuple[AdaptiveJobQueue, int]:
    """Create queue, optionally loading persisted weights and applying resume skip."""
    weights = ScanWeights()
    if load_weights and db is not None:
        rows = await db.load_scan_weights()
        if rows:
            weights = ScanWeights.from_rows(rows)

    queue = AdaptiveJobQueue.build(items, domains, weights=weights, epsilon=epsilon)
    skipped = 0
    if resume_check:
        skipped = await queue.filter_resume(resume_check)
    return queue, skipped


async def _run_single_adaptive_job(
    runner,
    job: AdaptiveJob,
    queue: AdaptiveJobQueue,
    *,
    timeout: float,
    done: int,
    passed: int,
    skipped: int,
    on_progress: ProgressCb | None,
) -> tuple[int, int]:
    results = [await runner.test_tcp(job.item, job.domain, timeout=timeout)]
    for result in results:
        ok = bool(result.success)
        queue.mark_done(job, passed=ok)
        done += 1
        if ok:
            passed += 1
        if on_progress:
            on_progress(done, skipped, passed)
    return done, passed


async def _flush_bridge_accumulator(
    runner,
    acc: BatchJobAccumulator,
    queue: AdaptiveJobQueue,
    *,
    timeout: float,
    done: int,
    passed: int,
    skipped: int,
    on_progress: ProgressCb | None,
) -> tuple[int, int]:
    jobs = acc.flush()
    if not jobs:
        return done, passed
    items = [j.item for j in jobs]
    domain = jobs[0].domain
    results = await runner._run_probe_batch(items, domain, timeout, "lua_bridge")
    for job, result in zip(jobs, results, strict=False):
        ok = bool(result.success)
        queue.mark_done(job, passed=ok)
        done += 1
        if ok:
            passed += 1
        if on_progress:
            on_progress(done, skipped, passed)
    return done, passed


async def run_adaptive_tcp_bridge(
    runner,
    queue: AdaptiveJobQueue,
    *,
    timeout: float = 5.0,
    bridge_batch: int = 500,
    stop_event: asyncio.Event | None = None,
    on_progress: ProgressCb | None = None,
) -> AdaptiveRunResult:
    """AQ bridge mode: accumulate same-domain jobs → ProbeBatchService batch flush."""
    done = 0
    skipped = 0
    passed = 0
    acc = BatchJobAccumulator(bridge_batch)

    while True:
        if stop_event and stop_event.is_set():
            break
        job = queue.pop()
        if job is None:
            done, passed = await _flush_bridge_accumulator(
                runner,
                acc,
                queue,
                timeout=timeout,
                done=done,
                passed=passed,
                skipped=skipped,
                on_progress=on_progress,
            )
            break

        if job.fanout:
            done, passed = await _flush_bridge_accumulator(
                runner,
                acc,
                queue,
                timeout=timeout,
                done=done,
                passed=passed,
                skipped=skipped,
                on_progress=on_progress,
            )
            done, passed = await _run_single_adaptive_job(
                runner,
                job,
                queue,
                timeout=timeout,
                done=done,
                passed=passed,
                skipped=skipped,
                on_progress=on_progress,
            )
            if stop_event and stop_event.is_set():
                break
            continue

        if not acc.push(job):
            done, passed = await _flush_bridge_accumulator(
                runner,
                acc,
                queue,
                timeout=timeout,
                done=done,
                passed=passed,
                skipped=skipped,
                on_progress=on_progress,
            )
            if not acc.push(job):
                done, passed = await _run_single_adaptive_job(
                    runner,
                    job,
                    queue,
                    timeout=timeout,
                    done=done,
                    passed=passed,
                    skipped=skipped,
                    on_progress=on_progress,
                )
                if stop_event and stop_event.is_set():
                    break
                continue

        if acc.is_full():
            done, passed = await _flush_bridge_accumulator(
                runner,
                acc,
                queue,
                timeout=timeout,
                done=done,
                passed=passed,
                skipped=skipped,
                on_progress=on_progress,
            )

        if stop_event and stop_event.is_set():
            break

    return AdaptiveRunResult(
        done=done,
        skipped=skipped,
        passed=passed,
        metrics=queue.metrics,
        weights=queue.weights,
    )


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
