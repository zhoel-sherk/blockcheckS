"""Unit tests for batch_probe scheduler, accumulator, and service."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from blockchecks.engine.adaptive_queue import AdaptiveJob
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.service.batch_models import (
    BatchContext,
    BatchProbeConfig,
    RunnerProbeDeps,
)
from blockchecks.service.batch_scheduler import BatchJobAccumulator, BatchScheduler
from blockchecks.service.batch_service import (
    ProbeBatchService,
    warn_fanout_bridge_once,
)


def _item(label: str) -> StrategyItem:
    return StrategyItem(label=label, strategy=f"fake:{label}")


def _job(label: str, domain: str, *, fanout: bool = False) -> AdaptiveJob:
    return AdaptiveJob(item=_item(label), domain=domain, fanout=fanout)


@pytest.mark.unit
def test_batch_scheduler_iter_batches() -> None:
    items = [_item(f"s{i}") for i in range(5)]
    chunks = BatchScheduler(2).iter_batches(items)
    assert len(chunks) == 3
    assert [len(c) for c in chunks] == [2, 2, 1]


@pytest.mark.unit
def test_batch_job_accumulator_cross_domain() -> None:
    acc = BatchJobAccumulator(3)
    assert acc.push(_job("a", "discord.com"))
    assert acc.push(_job("b", "discord.com"))
    assert acc.push(_job("c", "youtube.com"))
    assert len(acc) == 3
    assert acc.is_full()
    assert not acc.can_accept(_job("d", "signal.org"))
    jobs = acc.flush()
    assert len(jobs) == 3
    assert acc.domain is None
    assert acc.domains == []


@pytest.mark.unit
def test_batch_job_accumulator_dup_key_rejected() -> None:
    acc = BatchJobAccumulator(10)
    assert acc.push(_job("a", "discord.com"))
    assert not acc.can_accept(_job("a", "discord.com"))
    assert acc.push(_job("a", "youtube.com"))


@pytest.mark.unit
def test_batch_job_accumulator_rejects_fanout() -> None:
    acc = BatchJobAccumulator(10)
    assert not acc.can_accept(_job("a", "discord.com", fanout=True))


@pytest.mark.unit
def test_warn_fanout_bridge_once() -> None:
    warn_fanout_bridge_once()
    warn_fanout_bridge_once()


@pytest.mark.unit
@pytest.mark.asyncio(loop_scope="package")
async def test_probe_batch_service_classic_mock() -> None:
    calls: list[str] = []

    async def acquire() -> str:
        return "bs-p-0"

    async def release(ns: str) -> None:
        calls.append(f"release:{ns}")

    async def resolve(domain: str) -> tuple[str | None, str, str]:
        return "1.2.3.4", "ok", "doh"

    async def log_tcp_result(*_a, **_k) -> None:
        calls.append("log")

    deps = RunnerProbeDeps(
        python="python3",
        disable_ech=False,
        repeats=1,
        parallel_repeats=False,
        repeats_mode="fast",
        quick_break=False,
        try_wssize=False,
        lua_extra=[],
        timing_for=lambda item, t: (t, None),
        resolve_domain_dns=resolve,
        tcp_result_from_data=lambda item, domain, data: MagicMock(success=data.get("success")),
        log_tcp_result=log_tcp_result,
        next_probe_gen=lambda: 1,
        run_tcp_check=lambda *a, **k: {"success": True, "http_code": 200, "latency_ms": 50},
        acquire_ns=acquire,
        release_ns=release,
    )
    svc = ProbeBatchService(BatchProbeConfig(backend="classic"), deps)
    ctx = BatchContext(
        ns_name="",
        items=[_item("a"), _item("b")],
        domain="discord.com",
        batch_id=1,
    )
    result = await svc.run_batch(ctx, timeout=5.0)
    assert len(result.results) == 2
    assert result.backend == "classic"
    assert calls.count("log") == 2
    assert "release:bs-p-0" in calls


@pytest.mark.unit
@pytest.mark.asyncio(loop_scope="package")
async def test_probe_batch_service_lua_bridge_mock() -> None:
    booted = shutdown = 0

    class FakeSession:
        ns_name = "bs-p-0"

        def __init__(self, **_k) -> None:
            self.bridge = MagicMock()
            self.bridge.truncate_events = MagicMock()
            self.bridge.publish = MagicMock()
            self.bridge.drain_events = MagicMock(return_value=[])

        def boot(self) -> float:
            nonlocal booted
            booted += 1
            return 0.1

        def shutdown(self) -> None:
            nonlocal shutdown
            shutdown += 1

    import blockchecks.service.batch_service as bp

    original = bp.BridgeSession
    bp.BridgeSession = FakeSession
    try:
        deps = RunnerProbeDeps(
            python="python3",
            disable_ech=False,
            repeats=1,
            parallel_repeats=False,
            repeats_mode="fast",
            quick_break=False,
            try_wssize=False,
            lua_extra=[],
            timing_for=lambda item, t: (t, None),
            resolve_domain_dns=AsyncMock(return_value=(None, "", "")),
            tcp_result_from_data=lambda item, domain, data: MagicMock(success=True),
            log_tcp_result=AsyncMock(),
            next_probe_gen=lambda: 1,
            run_tcp_check=lambda *a, **k: {"success": True},
            acquire_ns=AsyncMock(return_value="bs-p-0"),
            release_ns=AsyncMock(),
        )
        svc = ProbeBatchService(BatchProbeConfig(backend="lua_bridge"), deps)
        ctx = BatchContext(
            ns_name="",
            items=[_item("a")],
            domain="discord.com",
            batch_id=2,
        )
        result = await svc.run_batch(ctx, 5.0)
        assert booted == 1
        assert shutdown == 1
        assert result.backend == "lua_bridge"
        assert result.settle_ms == 100.0
    finally:
        bp.BridgeSession = original


@pytest.mark.unit
async def test_probe_batch_service_recycles_on_memory_flag() -> None:
    booted = 0

    class FakeSession:
        ns_name = "bs-p-0"

        def __init__(self, **_k) -> None:
            self.bridge = MagicMock()
            self.bridge.truncate_events = MagicMock()
            self.bridge.publish = MagicMock()
            self.bridge.drain_events = MagicMock(return_value=[])

        def boot(self) -> float:
            nonlocal booted
            booted += 1
            return 0.1

        def shutdown(self) -> None:
            pass

    class FakeMonitor:
        def should_sample(self) -> bool:
            return True

        def record_ns(self, ns_name, pids=None) -> None:
            pass

        def worker_over_limit(self) -> bool:
            return False

        def recycle_candidates(self) -> list[tuple[int, str]]:
            return [(1234, "rss=999MiB > 512MiB")]

        def clear(self, pid=None) -> None:
            pass

    import blockchecks.service.batch_service as bp

    original = bp.BridgeSession
    bp.BridgeSession = FakeSession
    try:
        deps = RunnerProbeDeps(
            python="python3",
            disable_ech=False,
            repeats=1,
            parallel_repeats=False,
            repeats_mode="fast",
            quick_break=False,
            try_wssize=False,
            lua_extra=[],
            timing_for=lambda item, t: (t, None),
            resolve_domain_dns=AsyncMock(return_value=(None, "", "")),
            tcp_result_from_data=lambda item, domain, data: MagicMock(success=True),
            log_tcp_result=AsyncMock(),
            next_probe_gen=lambda: 1,
            run_tcp_check=lambda *a, **k: {"success": True},
            acquire_ns=AsyncMock(return_value="bs-p-0"),
            release_ns=AsyncMock(),
        )
        svc = ProbeBatchService(
            BatchProbeConfig(backend="lua_bridge"), deps, memory_monitor=FakeMonitor()
        )
        ctx = BatchContext(
            ns_name="",
            items=[_item("a")],
            domain="discord.com",
            batch_id=3,
        )
        result = await svc.run_batch(ctx, 5.0)
        assert booted == 2  # initial boot + recycle boot
        assert result.backend == "lua_bridge"
    finally:
        bp.BridgeSession = original
