"""Tests for domain denylist, run deadline, and adaptive scan wiring."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

from blockchecks.checkers.composite_runner import normalize_domains
from blockchecks.engine.adaptive_queue import AdaptiveJobQueue
from blockchecks.engine.adaptive_runner import run_adaptive_tcp
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.run_deadline import RunDeadline

pytestmark = pytest.mark.unit


def test_normalize_domains_comma_separated_argv():
    assert normalize_domains(["discord.com,discord.gg"]) == ["discord.com", "discord.gg"]


def test_normalize_domains_mixed_tokens():
    assert normalize_domains(["discord.com, discord.gg", "youtube.com"]) == [
        "discord.com",
        "discord.gg",
        "youtube.com",
    ]


def test_normalize_domains_dedupe_and_strip():
    assert normalize_domains([" a.com , b.com ", "a.com"]) == ["a.com", "b.com"]


def test_normalize_domains_default():
    out = normalize_domains(None)
    assert "discord.com" in out
    assert len(out) >= 2


@dataclass
class _FakeResult:
    success: bool
    item: StrategyItem
    domain: str


@pytest.mark.asyncio
async def test_adaptive_stops_mid_batch_when_deadline_sets_stop():
    """After each job in a batch, stop_event aborts remaining queue work."""
    items = [StrategyItem(label=f"s{i}", strategy=f"fake:repeats={i}") for i in range(6)]
    domains = ["a.com", "b.com", "c.com"]
    queue = AdaptiveJobQueue.build(items, domains, epsilon=0.0)
    stop = asyncio.Event()
    calls = 0

    class Runner:
        async def test_tcp(self, item, domain, timeout=5.0):
            nonlocal calls
            calls += 1
            if calls >= 2:
                stop.set()
            return _FakeResult(success=True, item=item, domain=domain)

        async def test_tcp_domains(self, item, domains, timeout=5.0, curl_parallel=4):
            nonlocal calls
            out = []
            for d in domains:
                calls += 1
                if calls >= 2:
                    stop.set()
                out.append(_FakeResult(success=True, item=item, domain=d))
            return out

    result = await run_adaptive_tcp(Runner(), queue, curl_parallel=3, stop_event=stop)
    # Stop fires mid-batch; we still mark the jobs already returned, but
    # must not drain the rest of the matrix.
    assert result.done >= 1
    assert result.done < len(items) * len(domains)
    assert stop.is_set()
    assert len(queue) > 0


@pytest.mark.asyncio
async def test_deadline_fires_and_sets_stop(capsys):
    stop = asyncio.Event()
    deadline = RunDeadline(stop, budget_sec=0.05)
    deadline.arm()
    await deadline.start_background()
    await asyncio.sleep(0.1)
    assert stop.is_set()
    assert deadline.triggered
    assert deadline.reason == "time_limit"
    out = capsys.readouterr().out
    assert "deadline" in out.lower() or "fired" in out.lower()
    await deadline.cancel()
