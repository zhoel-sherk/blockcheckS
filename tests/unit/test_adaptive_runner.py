"""Unit tests for adaptive_runner (AQ5–AQ6)."""

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

    async def test_tcp(self, item, domain, timeout=5.0):
        self.calls.append((item.label, [domain]))
        return _FakeResult(success=True, item=item, domain=domain)

    async def test_tcp_domains(self, item, domains, timeout=5.0, curl_parallel=4):
        self.calls.append((item.label, list(domains)))
        return [_FakeResult(success=True, item=item, domain=d) for d in domains]


@pytest.mark.asyncio
async def test_run_adaptive_tcp_single():
    items = [
        StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6"),
        StrategyItem(label="s2", strategy="oob:urp=b"),
    ]
    queue = AdaptiveJobQueue.build(items, ["discord.com"], epsilon=0.0)
    runner = _FakeRunner()
    result = await run_adaptive_tcp(runner, queue, curl_parallel=1)
    assert result.done == 2
    assert result.passed == 2
    assert len(runner.calls) == 2


@pytest.mark.asyncio
async def test_run_adaptive_tcp_b2_batch():
    items = [StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")]
    domains = ["discord.com", "discord.gg"]
    queue = AdaptiveJobQueue.build(items, domains, epsilon=0.0)
    runner = _FakeRunner()
    result = await run_adaptive_tcp(runner, queue, curl_parallel=4)
    assert result.done == 2
    assert result.passed == 2
    # B2: one test_tcp_domains call for both discord domains
    assert len(runner.calls) == 1
    assert set(runner.calls[0][1]) == set(domains)


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

    async def test_tcp(item, domain, timeout=5.0):
        stop.set()
        return _FakeResult(success=True, item=item, domain=domain)

    runner.test_tcp = test_tcp
    result = await run_adaptive_tcp(runner, queue, curl_parallel=1, stop_event=stop)
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

    async def fake_worker(runner, queue, stats, **kw):
        calls["n"] += 1
        stats.done += 1
        stats.passed += 1
        if kw.get("stop_event") is None:
            pass

    with patch(
        "blockchecks.engine.adaptive_runner._bridge_worker", side_effect=fake_worker
    ):
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
    weights.boost_pass = MagicMock()
    await _apply_provider_weights(store, weights, ["discord.com"])
    weights.boost_pass.assert_called_once()


@pytest.mark.unit
async def test_apply_provider_weights_skips_other_domain():
    from blockchecks.engine.adaptive_runner import _apply_provider_weights

    store = MagicMock()
    store.pass_strategies = AsyncMock(
        return_value=[{"domain": "youtube.com", "strategy": "fake:blob=stun"}]
    )
    weights = MagicMock()
    weights.boost_pass = MagicMock()
    await _apply_provider_weights(store, weights, ["discord.com"])
    weights.boost_pass.assert_not_called()


@pytest.mark.unit
async def test_apply_provider_weights_skips_missing_strategy():
    from blockchecks.engine.adaptive_runner import _apply_provider_weights

    store = MagicMock()
    store.pass_strategies = AsyncMock(return_value=[{"domain": "discord.com", "strategy": ""}])
    weights = MagicMock()
    weights.boost_pass = MagicMock()
    await _apply_provider_weights(store, weights, ["discord.com"])
    weights.boost_pass.assert_not_called()


async def _make_job(strategy="fake:blob=stun:repeats=6:tcp_ts=-1000", domain="discord.com", fanout=False):
    from blockchecks.engine.adaptive_runner import _bridge_worker  # noqa: F401
    return AdaptiveJob.from_item(StrategyItem(label=strategy, strategy=strategy), domain, fanout=fanout)


@pytest.mark.unit
async def test_bridge_worker_flushes_full_batch():
    from blockchecks.engine.adaptive_runner import _bridge_worker, _RunStats

    queue = MagicMock()
    results = [MagicMock(success=True), MagicMock(success=False)]
    runner = MagicMock()
    runner._run_probe_batch = AsyncMock(side_effect=[[r] for r in results])

    jobs = [await _make_job(domain=f"d{i}") for i in range(2)]
    pops = iter([jobs[0], jobs[1], None])
    queue.pop = MagicMock(side_effect=lambda **kw: next(pops))

    stats = _RunStats()
    progress = []
    await _bridge_worker(
        runner, queue, stats, timeout=5.0, bridge_batch=1,
        stop_event=None, on_progress=lambda d, s, p: progress.append((d, p)),
        active_domains=set(), domain_lock=asyncio.Lock(),
    )
    assert stats.done == 2
    assert stats.passed == 1
    assert runner._run_probe_batch.await_count == 2


@pytest.mark.unit
async def test_bridge_worker_fanout_run_single():
    from blockchecks.engine.adaptive_runner import _bridge_worker, _RunStats

    queue = MagicMock()
    job = await _make_job(fanout=True)
    pops = iter([job, None])
    queue.pop = MagicMock(side_effect=lambda **kw: next(pops))

    runner = MagicMock()
    runner.test_tcp = AsyncMock(return_value=MagicMock(success=True))

    stats = _RunStats()
    await _bridge_worker(runner, queue, stats, timeout=5.0, bridge_batch=50, stop_event=None,
                         on_progress=None, active_domains=set(), domain_lock=asyncio.Lock())
    assert stats.done == 1
    assert stats.passed == 1
    runner.test_tcp.assert_awaited_once()


@pytest.mark.unit
async def test_bridge_worker_stop_event_flushes():
    from blockchecks.engine.adaptive_runner import _bridge_worker, _RunStats

    stop = asyncio.Event()
    stop.set()
    queue = MagicMock()
    runner = MagicMock()
    runner._run_probe_batch = AsyncMock(return_value=[])

    stats = _RunStats()
    await _bridge_worker(runner, queue, stats, timeout=5.0, bridge_batch=50, stop_event=stop, on_progress=None)
    assert stats.done == 0


