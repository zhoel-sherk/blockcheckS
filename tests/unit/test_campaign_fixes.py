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
        async def _run_probe_batch(
            self, items, domain, timeout, backend, domains=None, stop_event=None
        ):
            nonlocal calls
            results = []
            for i, item in enumerate(items):
                if stop_event is not None and stop_event.is_set():
                    break
                d = domains[i] if domains and i < len(domains) else domain
                calls += 1
                if calls >= 2:
                    stop.set()
                results.append(_FakeResult(success=True, item=item, domain=d))
            return results

    result = await run_adaptive_tcp(
        Runner(),
        queue,
        curl_parallel=3,
        stop_event=stop,
        workers=1,
        bridge_batch=3,
    )
    # Stop fires mid-batch; remaining jobs are not drained.
    assert result.done >= 1
    assert result.done < len(items) * len(domains)
    assert stop.is_set()
    assert len(queue) > 0


@pytest.mark.asyncio
async def test_deadline_fires_and_sets_stop(caplog):
    stop = asyncio.Event()
    deadline = RunDeadline(stop, budget_sec=0.05)
    with caplog.at_level("INFO", logger="blockchecks"):
        deadline.arm()
        await deadline.start_background()
        await asyncio.sleep(0.1)
    assert stop.is_set()
    assert deadline.triggered
    assert deadline.reason == "time_limit"
    assert "deadline" in caplog.text.lower() or "fired" in caplog.text.lower()
    await deadline.cancel()
