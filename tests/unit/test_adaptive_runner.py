"""Tests for the adaptive TCP scan loop."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.engine.adaptive_queue import AdaptiveJob, AdaptiveJobQueue
from blockchecks.engine.adaptive_runner import build_adaptive_queue, run_adaptive_tcp
from blockchecks.engine.generators.base import StrategyItem

pytestmark = pytest.mark.unit


@dataclass
class _FakeResult:
    success: bool
    item: StrategyItem
    domain: str


class _FakeRunner:
    def __init__(self):
        self.calls: list[tuple[str, list[str]]] = []
        self.batch_backends: list[str] = []

    async def test_tcp(self, item, domain, timeout=5.0):
        self.calls.append((item.label, [domain]))
        return _FakeResult(success=True, item=item, domain=domain)

    async def test_tcp_domains(self, item, domains, timeout=5.0, curl_parallel=4):
        self.calls.append((item.label, list(domains)))
        return [_FakeResult(success=True, item=item, domain=d) for d in domains]

    async def _run_probe_batch(
        self, items, domain, timeout, backend, domains=None, stop_event=None
    ):
        self.batch_backends.append(backend)
        results = []
        for i, item in enumerate(items):
            d = domains[i] if domains and i < len(domains) else domain
            self.calls.append((item.label, [d]))
            results.append(_FakeResult(success=True, item=item, domain=d))
        return results


@pytest.mark.asyncio
async def test_run_adaptive_tcp_single():
    items = [
        StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6"),
        StrategyItem(label="s2", strategy="oob:urp=b"),
    ]
    queue = AdaptiveJobQueue.build(items, ["discord.com"], epsilon=0.0)
    runner = _FakeRunner()
    result = await run_adaptive_tcp(runner, queue, curl_parallel=1, workers=1)
    assert result.done == 2
    assert result.passed == 2
    assert len(runner.calls) == 2
    assert runner.batch_backends == ["lua_bridge"]


@pytest.mark.asyncio
async def test_run_adaptive_tcp_b2_batch():
    items = [StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")]
    domains = ["discord.com", "discord.gg"]
    queue = AdaptiveJobQueue.build(items, domains, epsilon=0.0)
    runner = _FakeRunner()
    result = await run_adaptive_tcp(runner, queue, curl_parallel=4)
    assert result.done == 2
    assert result.passed == 2
    assert runner.batch_backends == ["lua_bridge"]


@pytest.mark.asyncio
async def test_build_adaptive_queue_resume(temp_db):
    items = [StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")]
    await temp_db.log_tcp("s1", "discord.com", "PASS", 100.0, 200)

    async def resume(job):
        return job.domain == "discord.com"

    queue, skipped = await build_adaptive_queue(
        items,
        ["discord.com", "discord.gg"],
        temp_db,
        resume_check=resume,
    )
    assert skipped == 1
    assert len(queue) == 1


@pytest.mark.asyncio
async def test_build_adaptive_queue_skip_keys_not_allocated():
    """PERF-3: skip_keys never enter _pending; counted as resume skip."""
    items = [StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")]
    queue, skipped = await build_adaptive_queue(
        items,
        ["discord.com", "discord.gg"],
        None,
        load_weights=False,
        skip_keys={("s1", "discord.com")},
    )
    assert skipped == 1
    assert len(queue) == 1
    assert ("s1", "discord.com") not in queue._pending
    assert ("s1", "discord.com") in queue._done


@pytest.mark.asyncio
async def test_build_adaptive_queue_quarantine_skip_domains():
    """PERF-3: quarantine snapshot is applied at build, not after packing."""

    class _Q:
        def exclude_domains(self) -> set[str]:
            return {"dead.example"}

    items = [StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")]
    queue, skipped = await build_adaptive_queue(
        items,
        ["discord.com", "dead.example"],
        None,
        load_weights=False,
        quarantine=_Q(),
    )
    assert skipped == 0
    assert all(job.domain != "dead.example" for job in queue._pending.values())
    assert "dead.example" in queue.excluded_domains
    assert len(queue) == 1


@pytest.mark.asyncio
async def test_adaptive_pass_boosts_family_weight():
    items = [
        StrategyItem(label="std_fake_stun", strategy="fake:blob=stun:repeats=6"),
        StrategyItem(label="std_oob_b", strategy="oob:urp=b"),
    ]
    queue = AdaptiveJobQueue.build(items, ["discord.com"], epsilon=0.0)
    job = queue.pop()
    assert job is not None
    queue.mark_done(job, passed=True)
    if job.family == "fake":
        assert queue.weights.family.get("fake", 1.0) > 1.0
    else:
        # popped oob first — run fake and check boost
        job2 = queue.pop()
        assert job2 is not None
        queue.mark_done(job2, passed=True)
        assert queue.weights.family.get("fake", 1.0) > 1.0


@pytest.mark.asyncio
async def test_run_adaptive_tcp_stops_on_stop_event():
    items = [StrategyItem(label=f"s{i}", strategy=f"fake:blob=stun:repeats={i}") for i in range(5)]
    queue = AdaptiveJobQueue.build(items, ["discord.com"], epsilon=0.0)
    runner = _FakeRunner()
    stop = asyncio.Event()

    async def _run_probe_batch(items, domain, timeout, backend, domains=None, stop_event=None):
        stop.set()
        item = items[0]
        runner.calls.append((item.label, [domain]))
        return [_FakeResult(success=True, item=item, domain=domain)]

    runner._run_probe_batch = _run_probe_batch
    result = await run_adaptive_tcp(
        runner, queue, workers=1, bridge_batch=1, stop_event=stop
    )
    assert result.done == 1
    assert result.passed == 1
    assert len(queue) > 0


@pytest.mark.asyncio
async def test_build_adaptive_queue_provider_weights():
    """Provider pass_strategies boost AQ family weights for approved strategies."""
    from blockchecks.engine.adaptive_queue import ScanWeights
    from blockchecks.engine.adaptive_runner import _apply_provider_weights

    class FakeProviderStore:
        async def pass_strategies(self, *, approved_only=False):
            return [
                {
                    "strategy": "fake:blob=stun:repeats=6:tcp_ts=-1000",
                    "domain": "discord.com",
                    "protocol": "tcp",
                    "approved": 1,
                }
            ]

    weights = ScanWeights()
    await _apply_provider_weights(
        FakeProviderStore(),
        weights,
        ["discord.com", "youtube.com"],
    )
    # fake family gets boosted by the provider-approved strategy
    assert any(v > 1.0 for v in weights.family.values())


@pytest.mark.asyncio
async def test_build_adaptive_queue_provider_skips_other_domain():
    """Provider strategies for domains outside the scan are not boosted."""
    from blockchecks.engine.adaptive_queue import ScanWeights
    from blockchecks.engine.adaptive_runner import _apply_provider_weights

    class FakeProviderStore:
        async def pass_strategies(self, *, approved_only=False):
            return [
                {
                    "strategy": "fake:blob=stun:repeats=6",
                    "domain": "not-in-scan.com",
                    "approved": 1,
                }
            ]

    weights = ScanWeights()
    await _apply_provider_weights(FakeProviderStore(), weights, ["discord.com"])
    assert all(v == 1.0 for v in weights.family.values())


@pytest.mark.unit
async def test_run_adaptive_tcp_bridge_path():
    """lua_bridge=True routes to run_adaptive_tcp_bridge (workers)."""
    from blockchecks.engine.adaptive_runner import run_adaptive_tcp

    runner = MagicMock()
    queue = MagicMock()
    queue.metrics = MagicMock()
    queue.weights = MagicMock()
    stop = asyncio.Event()
    with patch(
        "blockchecks.engine.adaptive_runner.run_adaptive_tcp_bridge",
        return_value=MagicMock(
            done=3, skipped=0, passed=2, metrics=queue.metrics, weights=queue.weights
        ),
    ) as m_bridge:
        result = await run_adaptive_tcp(
            runner, queue, curl_parallel=1, lua_bridge=True, stop_event=stop, workers=2
        )
    assert result.done == 3
    assert result.passed == 2
    assert m_bridge.call_args.kwargs["workers"] == 2


@pytest.mark.unit
async def test_run_adaptive_tcp_bridge_workers(monkeypatch):
    """run_adaptive_tcp_bridge spawns N bridge workers and aggregates stats."""
    from blockchecks.engine.adaptive_runner import run_adaptive_tcp_bridge

    queue = MagicMock()
    queue.metrics = MagicMock()
    queue.weights = MagicMock()
    runner = MagicMock()
    stop = asyncio.Event()

    calls = {"n": 0}

    async def fake_worker(pool, queue, stats, **kw):
        calls["n"] += 1
        stats.done += 1
        stats.passed += 1

    with patch("blockchecks.engine.adaptive_runner._bridge_worker", side_effect=fake_worker):
        result = await run_adaptive_tcp_bridge(
            runner, queue, bridge_batch=50, stop_event=stop, workers=3
        )
    assert calls["n"] == 3
    assert result.done == 3
    assert result.passed == 3


@pytest.mark.unit
async def test_persist_adaptive_weights_empty():
    from blockchecks.engine.adaptive_runner import persist_adaptive_weights

    db = MagicMock()
    weights = MagicMock()
    weights.to_rows.return_value = []
    await persist_adaptive_weights(db, weights)
    db.save_scan_weights.assert_not_called()


@pytest.mark.unit
async def test_persist_adaptive_weights_rows():
    from blockchecks.engine.adaptive_runner import persist_adaptive_weights

    db = MagicMock()
    db.save_scan_weights = AsyncMock()
    weights = MagicMock()
    weights.to_rows.return_value = [{"family": "fake", "weight": 1.0}]
    await persist_adaptive_weights(db, weights)
    db.save_scan_weights.assert_called_once()


@pytest.mark.unit
async def test_apply_provider_weights_boosts():
    from blockchecks.engine.adaptive_runner import _apply_provider_weights

    store = MagicMock()
    store.pass_strategies = AsyncMock(
        return_value=[
            {"domain": "discord.com", "strategy": "fake:blob=stun:repeats=6:tcp_ts=-1000"}
        ]
    )
    weights = MagicMock()
    weights.boost_provider_once = MagicMock(return_value=True)
    await _apply_provider_weights(store, weights, ["discord.com"])
    weights.boost_provider_once.assert_called_once()


@pytest.mark.unit
async def test_apply_provider_weights_skips_other_domain():
    from blockchecks.engine.adaptive_runner import _apply_provider_weights

    store = MagicMock()
    store.pass_strategies = AsyncMock(
        return_value=[{"domain": "youtube.com", "strategy": "fake:blob=stun"}]
    )
    weights = MagicMock()
    weights.boost_provider_once = MagicMock(return_value=True)
    await _apply_provider_weights(store, weights, ["discord.com"])
    weights.boost_provider_once.assert_not_called()


@pytest.mark.unit
async def test_apply_provider_weights_skips_missing_strategy():
    from blockchecks.engine.adaptive_runner import _apply_provider_weights

    store = MagicMock()
    store.pass_strategies = AsyncMock(return_value=[{"domain": "discord.com", "strategy": ""}])
    weights = MagicMock()
    weights.boost_provider_once = MagicMock(return_value=True)
    await _apply_provider_weights(store, weights, ["discord.com"])
    weights.boost_provider_once.assert_not_called()


async def _make_job(
    strategy="fake:blob=stun:repeats=6:tcp_ts=-1000", domain="discord.com", fanout=False
):
    return AdaptiveJob.from_item(
        StrategyItem(label=strategy, strategy=strategy), domain, fanout=fanout
    )


async def _run_bridge_worker(
    runner,
    queue,
    stats,
    *,
    bridge_batch=50,
    stop_event=None,
    on_progress=None,
    isolate=True,
    quarantine=None,
    timeout=5.0,
):
    from blockchecks.engine.adaptive_runner import _bridge_worker
    from blockchecks.engine.bridge_worker_pool import BridgeWorkerPool

    if not hasattr(queue, "excluded_domains"):
        queue.excluded_domains = set()
    pool = BridgeWorkerPool(
        runner,
        timeout=timeout,
        stop_event=stop_event,
        isolate=isolate,
        active_domains=set(),
        quarantine=quarantine,
        excluded_domains=queue.excluded_domains,
    )
    await _bridge_worker(
        pool,
        queue,
        stats,
        bridge_batch=bridge_batch,
        on_progress=on_progress,
    )


@pytest.mark.unit
async def test_bridge_worker_accounts_partial_batch_as_skipped():
    from blockchecks.engine.adaptive_runner import _RunStats
    from blockchecks.engine.results import TcpTestResult

    queue = MagicMock()
    jobs = [await _make_job(domain=f"d{i}") for i in range(3)]
    pops = iter([jobs[0], jobs[1], jobs[2], None])
    queue.pop = MagicMock(side_effect=lambda **kw: next(pops))

    runner = MagicMock()
    runner._run_probe_batch = AsyncMock(
        return_value=[
            TcpTestResult(item=jobs[0].item, domain=jobs[0].domain, success=True),
            TcpTestResult(item=jobs[1].item, domain=jobs[1].domain, success=False),
        ]
    )

    stats = _RunStats()
    await _run_bridge_worker(
        runner,
        queue,
        stats,
        bridge_batch=3,
    )
    assert stats.done == 3
    assert stats.passed == 1
    assert stats.skipped == 1


@pytest.mark.unit
async def test_bridge_worker_flushes_full_batch():
    from blockchecks.engine.adaptive_runner import _RunStats

    queue = MagicMock()
    results = [MagicMock(success=True), MagicMock(success=False)]
    runner = MagicMock()
    runner._run_probe_batch = AsyncMock(side_effect=[[r] for r in results])

    jobs = [await _make_job(domain=f"d{i}") for i in range(2)]
    pops = iter([jobs[0], jobs[1], None])
    queue.pop = MagicMock(side_effect=lambda **kw: next(pops))

    stats = _RunStats()
    progress = []
    await _run_bridge_worker(
        runner,
        queue,
        stats,
        bridge_batch=1,
        on_progress=lambda d, s, p: progress.append((d, p)),
    )
    assert stats.done == 2
    assert stats.passed == 1
    assert runner._run_probe_batch.await_count == 2


@pytest.mark.unit
async def test_bridge_worker_fanout_run_single():
    from blockchecks.engine.adaptive_runner import _RunStats

    queue = MagicMock()
    job = await _make_job(fanout=True)
    pops = iter([job, None])
    queue.pop = MagicMock(side_effect=lambda **kw: next(pops))

    runner = MagicMock()
    runner.test_tcp = AsyncMock(return_value=MagicMock(success=True))

    stats = _RunStats()
    await _run_bridge_worker(runner, queue, stats, bridge_batch=50)
    assert stats.done == 1
    assert stats.passed == 1
    runner.test_tcp.assert_awaited_once()


@pytest.mark.unit
async def test_bridge_worker_stop_event_flushes():
    from blockchecks.engine.adaptive_runner import _RunStats

    stop = asyncio.Event()
    stop.set()
    queue = MagicMock()
    runner = MagicMock()
    runner._run_probe_batch = AsyncMock(return_value=[])

    stats = _RunStats()
    await _run_bridge_worker(runner, queue, stats, bridge_batch=50, stop_event=stop)
    assert stats.done == 0


@pytest.mark.unit
async def test_bridge_worker_progress_before_batch_flush():
    """on_progress fires incrementally (done + acc) even before a big-batch flush."""
    from blockchecks.engine.adaptive_runner import _RunStats

    queue = MagicMock()
    runner = MagicMock()
    runner._run_probe_batch = AsyncMock(
        side_effect=lambda items, domain, timeout, backend, domains=None, stop_event=None: [
            MagicMock(success=True) for _ in items
        ]
    )

    # 3 jobs, bridge_batch=5 → a single flush at the end.
    jobs = [await _make_job(domain=f"d{i}") for i in range(3)]
    pops = iter([jobs[0], jobs[1], jobs[2], None])
    queue.pop = MagicMock(side_effect=lambda **kw: next(pops))

    stats = _RunStats()
    progress: list[tuple[int, int]] = []
    await _run_bridge_worker(
        runner,
        queue,
        stats,
        bridge_batch=5,
        on_progress=lambda d, s, p: progress.append((d, p)),
    )
    # progress reported for each accumulated job (1, 2, 3) before the flush,
    # plus the final flush progress (3).
    reported = [d for d, _ in progress]
    assert 1 in reported and 2 in reported
    assert stats.done == 3


@pytest.mark.asyncio
@pytest.mark.unit
async def test_aq_logs_lua_bridge_backend(caplog):
    items = [StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")]
    queue = AdaptiveJobQueue.build(items, ["discord.com"], epsilon=0.0)
    runner = _FakeRunner()
    with caplog.at_level("INFO"):
        await run_adaptive_tcp(runner, queue, curl_parallel=1, workers=1)
    assert "backend=lua_bridge" in caplog.text


@pytest.mark.asyncio
@pytest.mark.unit
async def test_aq_multi_domain_uses_bridge_batch(caplog):
    items = [StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")]
    domains = ["discord.com", "discord.gg"]
    queue = AdaptiveJobQueue.build(items, domains, epsilon=0.0)
    runner = _FakeRunner()
    with caplog.at_level("INFO"):
        await run_adaptive_tcp(runner, queue, curl_parallel=4, workers=1)
    assert "backend=lua_bridge" in caplog.text
    assert runner.batch_backends == ["lua_bridge"]


@pytest.mark.asyncio
@pytest.mark.unit
async def test_apply_provider_weights_idempotent():
    """Provider boosts apply at most once per strategy per process (ENG-3)."""
    from blockchecks.engine.adaptive_queue import ScanWeights
    from blockchecks.engine.adaptive_runner import _apply_provider_weights

    store = MagicMock()
    store.pass_strategies = AsyncMock(
        return_value=[
            {"domain": "discord.com", "strategy": "fake:blob=stun:repeats=6:tcp_ts=-1000"}
        ]
    )
    weights = ScanWeights()
    await _apply_provider_weights(store, weights, ["discord.com"])
    first_fake = weights.family.get("fake", 1.0)
    await _apply_provider_weights(store, weights, ["discord.com"])
    assert weights.family.get("fake", 1.0) == first_fake


@pytest.mark.asyncio
@pytest.mark.unit
async def test_aq_quarantine_skip_domains_not_probed():
    """Dead domains skipped at queue build are never probed (ENG-6.1)."""
    items = [StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")]
    domains = ["discord.com", "youtube.com"]
    queue = AdaptiveJobQueue.build(
        items, domains, epsilon=0.0, skip_domains={"youtube.com"}
    )
    runner = _FakeRunner()
    result = await run_adaptive_tcp(runner, queue, workers=1)
    assert result.done == 1
    assert result.passed == 1
    assert len(queue) == 0
    assert all(c[1] != ["youtube.com"] for c in runner.calls)


@pytest.mark.asyncio
@pytest.mark.unit
async def test_bridge_worker_stop_empty_and_fanout():
    from blockchecks.engine.adaptive_runner import _RunStats

    stats = _RunStats()
    runner = MagicMock()
    runner._run_probe_batch = AsyncMock(return_value=[])
    runner.test_tcp = AsyncMock(return_value=MagicMock(success=True))
    queue = MagicMock()
    queue.pop = MagicMock(return_value=None)

    stop = asyncio.Event()
    stop.set()
    await _run_bridge_worker(runner, queue, stats, bridge_batch=50, stop_event=stop)
    runner.test_tcp.assert_not_called()

    await _run_bridge_worker(runner, queue, _RunStats(), bridge_batch=50)
    runner.test_tcp.assert_not_called()

    job = await _make_job(fanout=True)
    pops = iter([job, None])
    queue.pop = MagicMock(side_effect=lambda **kw: next(pops))
    await _run_bridge_worker(runner, queue, _RunStats(), bridge_batch=50)
    runner.test_tcp.assert_awaited_once()


@pytest.mark.unit
async def test_bridge_worker_pool_claim_isolation():
    """Two workers cannot claim the same domain while isolation is enabled."""
    from blockchecks.engine.bridge_worker_pool import DomainIsolationPool

    pool = DomainIsolationPool(enabled=True)
    assert await pool.claim_domain("a.com")
    assert not await pool.claim_domain("a.com")
    await pool.release_domains(["a.com"])
    assert await pool.claim_domain("a.com")


@pytest.mark.unit
async def test_bridge_worker_pool_parallel_claims():
    from blockchecks.engine.bridge_worker_pool import DomainIsolationPool

    pool = DomainIsolationPool(enabled=True)
    results = await asyncio.gather(
        pool.claim_domain("a.com"),
        pool.claim_domain("b.com"),
        pool.claim_domain("a.com"),
    )
    assert results == [True, True, False]
    await pool.release_domains(["a.com", "b.com"])
    assert await pool.claim_domain("a.com")
