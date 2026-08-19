"""Unit tests for batch_probe scheduler, accumulator, and service."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

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
        resolve_domain_ips=lambda domain: [],
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
            resolve_domain_ips=lambda domain: [],
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
            resolve_domain_ips=lambda domain: [],
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


@pytest.mark.unit
async def test_run_batch_generic_exception_yields_fail_results() -> None:
    """H2: any error in the sync probe loop becomes per-item failure results."""
    logged: list[str] = []

    async def log_tcp_result(item, dom, probe_result, **_k) -> None:
        logged.append(dom)

    async def acquire() -> str:
        return "bs-p-0"

    async def release(ns: str) -> None:
        pass

    deps = RunnerProbeDeps(
        python="python3",
        disable_ech=False,
        repeats=1,
        parallel_repeats=False,
        repeats_mode="fast",
        quick_break=False,
        resolve_domain_ips=lambda domain: [],
        try_wssize=False,
        lua_extra=[],
        timing_for=lambda item, t: (t, None),
        resolve_domain_dns=AsyncMock(return_value=(None, "", "")),
        tcp_result_from_data=lambda item, domain, data: MagicMock(
            success=False, error=data.get("error", "")
        ),
        log_tcp_result=log_tcp_result,
        next_probe_gen=lambda: 1,
        run_tcp_check=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
        acquire_ns=acquire,
        release_ns=release,
    )
    svc = ProbeBatchService(BatchProbeConfig(backend="classic"), deps)
    ctx = BatchContext(
        ns_name="",
        items=[_item("a"), _item("b")],
        domain="discord.com",
        batch_id=9,
    )
    result = await svc.run_batch(ctx, 5.0)
    assert len(result.results) == 2
    assert all(not r.success for r in result.results)
    assert logged == ["discord.com", "discord.com"]


@pytest.mark.unit
async def test_wssize_retry_skips_config_items() -> None:
    """H3: wssize retry must not fire for config strategies (path, not inline text)."""
    classic_calls: list[tuple] = []

    async def acquire() -> str:
        return "bs-p-0"

    async def release(ns: str) -> None:
        pass

    def run_tcp_check(*args, **kwargs):
        classic_calls.append((args, kwargs))
        return {"success": False}

    config_item = StrategyItem(label="cfg", strategy="/tmp/some_config.conf", is_config=True)
    inline_item = StrategyItem(label="inline", strategy="fake:blob=stun:repeats=6")

    deps = RunnerProbeDeps(
        python="python3",
        disable_ech=False,
        repeats=1,
        parallel_repeats=False,
        repeats_mode="fast",
        resolve_domain_ips=lambda domain: [],
        quick_break=False,
        try_wssize=True,
        lua_extra=[],
        timing_for=lambda item, t: (t, None),
        resolve_domain_dns=AsyncMock(return_value=(None, "", "")),
        tcp_result_from_data=lambda item, domain, data: MagicMock(success=data.get("success")),
        log_tcp_result=AsyncMock(),
        next_probe_gen=lambda: 1,
        run_tcp_check=run_tcp_check,
        acquire_ns=acquire,
        release_ns=release,
    )
    svc = ProbeBatchService(BatchProbeConfig(backend="classic"), deps)
    ctx = BatchContext(
        ns_name="",
        items=[config_item, inline_item],
        domain="discord.com",
        batch_id=10,
    )
    await svc.run_batch(ctx, 5.0)

    # config item: 1 call, no wssize retry; inline item: 1 original + 1 wssize retry
    assert len(classic_calls) == 3
    config_args = classic_calls[0][0]
    assert "wssize" not in str(config_args)
    wssize_calls = [a for a, k in classic_calls if "wssize" in str(a)]
    assert len(wssize_calls) == 1


@pytest.mark.unit
def test_run_tcp_check_bridge_sets_bridge_applied_flag(tmp_path) -> None:
    """H6/T4: APPLIED event presence is surfaced as bridge_applied."""
    import json as _json

    from blockchecks.service.batch_bridge_probe import run_tcp_check_bridge

    class FakeBridge:
        def __init__(self, events: list[str]):
            self._events = events

        def truncate_events(self):
            pass

        def publish(self, strategy_id, gen, cmd=None):
            pass

        def drain_events(self, since_gen=0):
            from blockchecks.service.lua_bridge_ipc import BridgeEvent

            return [
                BridgeEvent.from_line(_json.dumps({"event": e, "gen": since_gen + 1}))
                for e in self._events
            ]

    class FakeSession:
        ns_name = "bs-p-0"

        def __init__(self, events: list[str]):
            self.bridge = FakeBridge(events)

    with patch(
        "blockchecks.service.batch_bridge_probe.invoke_curl_probe_worker",
        side_effect=lambda *a, **k: {
            "success": True,
            "http_code": 200,
            "latency_ms": 50,
        },
    ):
        applied = run_tcp_check_bridge(
            FakeSession(["APPLIED"]), 1, 1, "fake:x", "discord.com", 5.0, "/usr/bin/python3"
        )
        missing = run_tcp_check_bridge(
            FakeSession([]), 2, 2, "fake:x", "discord.com", 5.0, "/usr/bin/python3"
        )
    assert applied["bridge_applied"] is True, f"applied={applied}"
    assert missing["bridge_applied"] is False
    assert missing["bridge_events"] == []


@pytest.mark.unit
def test_next_probe_gen_monotonic() -> None:
    """H7: probe gen strictly increases across bridge probes (incl. wssize retry)."""
    from blockchecks.engine.async_runner import AsyncTestRunner

    runner = AsyncTestRunner(pool_size=1)
    seen = [runner._next_probe_gen() for _ in range(5)]
    assert seen == [1, 2, 3, 4, 5]
    assert len(set(seen)) == 5


@pytest.mark.unit
async def test_recycle_preserves_strategy_idx_and_events() -> None:
    """H9: after a memory-driven recycle, the next probe still publishes the
    correct strategy id and collects APPLIED events (no torn state)."""
    booted = 0
    published: list[tuple[int, int]] = []

    class FakeSession:
        ns_name = "bs-p-0"

        def __init__(self, **_k) -> None:
            self.bridge = MagicMock()
            self.bridge.truncate_events = MagicMock()
            self.bridge.publish = MagicMock(
                side_effect=lambda sid, gen, cmd=None: published.append((sid, gen))
            )
            self.bridge.drain_events = MagicMock(return_value=[MagicMock(event="APPLIED", gen=1)])

        def boot(self) -> float:
            nonlocal booted
            booted += 1
            return 0.1

        def shutdown(self) -> None:
            pass

    class FakeMonitor:
        _recycle_once = True

        def should_sample(self) -> bool:
            return True

        def record_ns(self, ns_name, pids=None) -> None:
            pass

        def worker_over_limit(self) -> bool:
            return False

        def recycle_candidates(self) -> list[tuple[int, str]]:
            if self._recycle_once:
                self._recycle_once = False
                return [(1234, "leak=99.0MiB/s > 8.0MiB/s")]
            return []

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
            resolve_domain_ips=lambda domain: [],
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
            items=[_item("a"), _item("b"), _item("c")],
            domain="discord.com",
            batch_id=4,
        )
        await svc.run_batch(ctx, 5.0)
        assert booted == 2  # initial + recycle
        # 3 probes, each published id = 1,2,3 (strategy position in batch)
        assert [p[0] for p in published] == [1, 2, 3]
        assert len(published) == 3
    finally:
        bp.BridgeSession = original


@pytest.mark.unit
async def test_debug_env_toggle_restarts_lua_daemon() -> None:
    """SIGUSR1 debug toggle: env change mid-batch forces a daemon reboot."""
    import os

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

    import blockchecks.service.batch_service as bp

    original = bp.BridgeSession
    bp.BridgeSession = FakeSession
    os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)
    try:
        deps = RunnerProbeDeps(
            python="python3",
            disable_ech=False,
            repeats=1,
            resolve_domain_ips=lambda domain: [],
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

        # SIGUSR1 arrives mid-batch: _debug_env() flips between boots → restart.
        seq = iter(["", "1", "1"])
        calls = {"boots": 0, "env_calls": 0}

        def fake_debug_env():
            calls["env_calls"] += 1
            try:
                return next(seq)
            except StopIteration:
                return "1"

        orig_debug_env = bp._debug_env
        bp._debug_env = fake_debug_env
        orig_boot = FakeSession.boot

        def booting(self):
            calls["boots"] += 1
            return 0.1

        FakeSession.boot = booting
        ctx = BatchContext(
            ns_name="",
            items=[_item("a"), _item("b")],
            domain="discord.com",
            batch_id=5,
        )
        await svc.run_batch(ctx, 5.0)
        assert calls["boots"] >= 2, f"expected restart on debug toggle, boots={calls['boots']}"
    finally:
        FakeSession.boot = orig_boot
        bp._debug_env = orig_debug_env
        bp.BridgeSession = original
        os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)


def _minimal_deps(**overrides):
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
        resolve_domain_ips=lambda domain: [],
        resolve_domain_dns=AsyncMock(return_value=("1.2.3.4", "ok", "doh")),
        tcp_result_from_data=lambda item, domain, data: MagicMock(success=data.get("success")),
        log_tcp_result=AsyncMock(),
        next_probe_gen=lambda: 1,
        run_tcp_check=lambda *a, **k: {"success": True, "http_code": 200},
        acquire_ns=AsyncMock(return_value="bs-p-0"),
        release_ns=AsyncMock(),
    )
    for k, v in overrides.items():
        setattr(deps, k, v)
    return deps


@pytest.mark.unit
@pytest.mark.asyncio(loop_scope="package")
async def test_run_batch_stop_event_skips_acquire() -> None:
    """A graceful stop must not acquire a netns or run any probe."""
    import asyncio

    acquired = []
    deps = _minimal_deps(
        acquire_ns=AsyncMock(side_effect=lambda: acquired.append(1) or "bs-p-0"),
        release_ns=AsyncMock(),
    )
    svc = ProbeBatchService(BatchProbeConfig(backend="classic"), deps)
    ctx = BatchContext(
        ns_name="",
        items=[_item("a"), _item("b")],
        domain="discord.com",
        batch_id=1,
    )
    stop = asyncio.Event()
    stop.set()
    result = await svc.run_batch(ctx, timeout=5.0, stop_event=stop)
    assert not acquired, "acquire_ns must not be called when stopped"
    assert len(result.results) == 2
    assert all(not r.success for r in result.results)
    assert all(getattr(r, "error", "") == "stopped before probe" for r in result.results)


@pytest.mark.unit
@pytest.mark.asyncio(loop_scope="package")
async def test_run_batch_acquire_timeout_returns_empty() -> None:
    """A busy pool (acquire never resolves) must not deadlock the stop."""
    import asyncio

    async def never_acquire():
        await asyncio.sleep(3600)
        return "bs-p-0"

    deps = _minimal_deps(acquire_ns=never_acquire, release_ns=AsyncMock())
    svc = ProbeBatchService(BatchProbeConfig(backend="classic"), deps)
    ctx = BatchContext(
        ns_name="",
        items=[_item("a")],
        domain="discord.com",
        batch_id=1,
    )
    with patch("blockchecks.service.batch_service.ACQUIRE_NS_TIMEOUT", 0.05):
        result = await svc.run_batch(ctx, timeout=5.0)
    assert len(result.results) == 1
    assert not result.results[0].success
