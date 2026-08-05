"""Unit tests for adaptive_runner (AQ5–AQ6)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

from blockchecks.engine.adaptive_queue import AdaptiveJobQueue
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
