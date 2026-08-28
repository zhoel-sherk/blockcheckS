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
    NS_POOL_EXHAUSTED,
    STOPPED_BEFORE_PROBE,
    ProbeBatchService,
    pool_exhausted_total,
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
async def test_probe_batch_service_classic_removed() -> None:
    """Campaign batch no longer restarts nfqws2 per strategy."""
    import inspect

    from blockchecks.service import batch_service as bp

    src = inspect.getsource(bp.ProbeBatchService)
    assert "_run_classic_batch" not in src
    assert "_run_lua_bridge_batch" in src


@pytest.mark.unit
@pytest.mark.asyncio(loop_scope="package")
async def test_probe_batch_service_lua_bridge_mock() -> None:
    booted = shutdown = 0

    class FakeSession:
        ns_name = "bs-p-0"

        def __init__(self, **_k) -> None:
            self.bridge = MagicMock()
            self.bridge.truncate_events = MagicMock()
            # Fence reads heartbeat: return fresh age so readiness passes.
            self.bridge.heartbeat_age = MagicMock(return_value=0.0)
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
    # Fence stub: production calls run_tcp_check_bridge once post-boot;
    # keep the probe-level publish/call assertions untouched here.
    real_bridge_probe = bp.run_tcp_check_bridge
    bp.run_tcp_check_bridge = lambda *a, **k: {
        "success": True,
        "bridge_applied": True,
        "bridge_events": ["APPLIED"],
    }
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
        bp.run_tcp_check_bridge = real_bridge_probe
        bp.BridgeSession = original


@pytest.mark.unit
async def test_probe_batch_service_recycles_on_memory_flag() -> None:
    booted = 0

    class FakeSession:
        ns_name = "bs-p-0"

        def __init__(self, **_k) -> None:
            self.bridge = MagicMock()
            self.bridge.truncate_events = MagicMock()
            # Fence reads heartbeat: return fresh age so readiness passes.
            self.bridge.heartbeat_age = MagicMock(return_value=0.0)
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
    # Fence stub: production calls run_tcp_check_bridge once post-boot;
    # keep the probe-level publish/call assertions untouched here.
    real_bridge_probe = bp.run_tcp_check_bridge
    bp.run_tcp_check_bridge = lambda *a, **k: {
        "success": True,
        "bridge_applied": True,
        "bridge_events": ["APPLIED"],
    }
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
        bp.run_tcp_check_bridge = real_bridge_probe
        bp.BridgeSession = original


@pytest.mark.unit
async def test_run_batch_generic_exception_yields_fail_results() -> None:
    """Any error in the sync probe loop becomes per-item failure results."""
    logged: list[str] = []

    async def log_tcp_result(item, dom, probe_result, **_k) -> None:
        logged.append(dom)

    class BoomSession:
        def __init__(self, **_k) -> None:
            raise RuntimeError("boom")

    import blockchecks.service.batch_service as bp

    original = bp.BridgeSession
    bp.BridgeSession = BoomSession
    try:
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
            run_tcp_check=lambda *a, **k: {"success": False},
            acquire_ns=AsyncMock(return_value="bs-p-0"),
            release_ns=AsyncMock(),
        )
        svc = ProbeBatchService(BatchProbeConfig(backend="lua_bridge"), deps)
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
    finally:
        bp.BridgeSession = original


@pytest.mark.unit
async def test_wssize_retry_removed_from_campaign_batch() -> None:
    import inspect

    from blockchecks.service.batch_service import ProbeBatchService

    assert "_maybe_wssize_retry" not in inspect.getsource(ProbeBatchService)


@pytest.mark.unit
def test_run_tcp_check_bridge_sets_bridge_applied_flag(tmp_path) -> None:
    """APPLIED event presence is surfaced as bridge_applied."""
    import json as _json

    from blockchecks.service.batch_bridge_probe import run_tcp_check_bridge

    class FakeBridge:
        def __init__(self, events: list[str]):
            self._events = events

        def truncate_events(self):
            pass

        def publish(self, strategy_id, gen, cmd=None):
            pass

        def drain_events(self, since_gen=0, expect_id=None):
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
    """Probe gen strictly increases across bridge probes (incl. wssize retry)."""
    from blockchecks.engine.async_runner import AsyncTestRunner

    runner = AsyncTestRunner(pool_size=1)
    seen = [runner._next_probe_gen() for _ in range(5)]
    assert seen == [1, 2, 3, 4, 5]
    assert len(set(seen)) == 5


@pytest.mark.unit
async def test_recycle_preserves_strategy_idx_and_events() -> None:
    """After a memory-driven recycle, the next probe still publishes the
    correct strategy id and collects APPLIED events (no torn state)."""
    booted = 0
    published: list[tuple[int, int]] = []

    class FakeSession:
        ns_name = "bs-p-0"

        def __init__(self, **_k) -> None:
            self.bridge = MagicMock()
            self.bridge.truncate_events = MagicMock()
            # Fence reads heartbeat: return fresh age so readiness passes.
            self.bridge.heartbeat_age = MagicMock(return_value=0.0)
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
    # Fence + probe stub that mirrors the real publish side effects so the
    # per-probe publish-id assertions below keep working.
    real_bridge_probe = bp.run_tcp_check_bridge

    def _publishing_probe(session, strategy_id, gen, *a, **k):
        session.bridge.truncate_events()
        session.bridge.publish(strategy_id, gen)
        return {"success": True, "bridge_applied": True, "bridge_events": ["APPLIED"]}

    bp.run_tcp_check_bridge = _publishing_probe
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
        # 3 probes, each published id = position in batch (fence is
        # heartbeat-based now and does not publish).
        assert [p[0] for p in published] == [1, 2, 3]
        assert len(published) == 3
    finally:
        bp.run_tcp_check_bridge = real_bridge_probe
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
            # Fence reads heartbeat: return fresh age so readiness passes.
            self.bridge.heartbeat_age = MagicMock(return_value=0.0)
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
    # Fence stub: production calls run_tcp_check_bridge once post-boot;
    # keep the probe-level publish/call assertions untouched here.
    real_bridge_probe = bp.run_tcp_check_bridge
    bp.run_tcp_check_bridge = lambda *a, **k: {
        "success": True,
        "bridge_applied": True,
        "bridge_events": ["APPLIED"],
    }
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
        bp.run_tcp_check_bridge = real_bridge_probe
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

    from blockchecks.engine.async_runner import _tcp_row_status
    from blockchecks.engine.results import TcpTestResult

    statuses: list[str] = []

    async def log_result(item, dom, probe_result, **kw):
        statuses.append(_tcp_row_status(probe_result))

    acquired = []
    deps = _minimal_deps(
        acquire_ns=AsyncMock(side_effect=lambda: acquired.append(1) or "bs-p-0"),
        release_ns=AsyncMock(),
        tcp_result_from_data=lambda item, domain, data: TcpTestResult(
            item=item,
            domain=domain,
            success=bool(data.get("success")),
            error=data.get("error") or "",
        ),
        log_tcp_result=log_result,
    )
    svc = ProbeBatchService(BatchProbeConfig(backend="lua_bridge"), deps)
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
    assert all(r.error == STOPPED_BEFORE_PROBE for r in result.results)
    assert statuses == ["SKIPPED", "SKIPPED"]


@pytest.mark.unit
@pytest.mark.asyncio(loop_scope="package")
async def test_run_batch_acquire_timeout_returns_empty() -> None:
    """A busy pool (acquire never resolves) must not deadlock the stop."""
    import asyncio

    import blockchecks.service.batch_service as bp

    bp._pool_exhausted_total = 0

    async def never_acquire():
        await asyncio.sleep(3600)
        return "bs-p-0"

    deps = _minimal_deps(acquire_ns=never_acquire, release_ns=AsyncMock())
    svc = ProbeBatchService(BatchProbeConfig(backend="lua_bridge"), deps)
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
    assert result.results[0].error == NS_POOL_EXHAUSTED
    assert result.results[0].error != STOPPED_BEFORE_PROBE
    assert pool_exhausted_total() == 1


@pytest.mark.unit
@pytest.mark.asyncio(loop_scope="package")
async def test_item_domains_length_mismatch_raises() -> None:
    ctx = BatchContext(
        ns_name="",
        items=[_item("a"), _item("b")],
        domain="discord.com",
        domains=["discord.com"],
        batch_id=1,
    )
    with pytest.raises(ValueError, match="domains length"):
        ctx.item_domains()


@pytest.mark.unit
def test_daemon_heartbeat_stale_when_age_none() -> None:
    """Missing heartbeat (age None) must fail closed — daemon treated as dead."""
    session = MagicMock()
    session.ns_name = "bs-p-stale"
    session.bridge.heartbeat_age.return_value = None
    svc = ProbeBatchService(BatchProbeConfig(backend="lua_bridge"), MagicMock())
    assert svc._daemon_heartbeat_stale(session) is True


@pytest.mark.unit
def test_daemon_heartbeat_stale_on_oserror() -> None:
    """heartbeat_age OSError must fail closed, not proceed to probe."""
    session = MagicMock()
    session.ns_name = "bs-p-err"
    session.bridge.heartbeat_age.side_effect = OSError("stat failed")
    svc = ProbeBatchService(BatchProbeConfig(backend="lua_bridge"), MagicMock())
    assert svc._daemon_heartbeat_stale(session) is True


@pytest.mark.unit
def test_daemon_heartbeat_stale_when_fresh() -> None:
    session = MagicMock()
    session.ns_name = "bs-p-fresh"
    session.bridge.heartbeat_age.return_value = 0.1
    svc = ProbeBatchService(BatchProbeConfig(backend="lua_bridge"), MagicMock())
    assert svc._daemon_heartbeat_stale(session) is False


@pytest.mark.unit
def test_daemon_heartbeat_stale_when_old() -> None:
    session = MagicMock()
    session.ns_name = "bs-p-old"
    session.bridge.heartbeat_age.return_value = 5.0
    svc = ProbeBatchService(BatchProbeConfig(backend="lua_bridge"), MagicMock())
    assert svc._daemon_heartbeat_stale(session) is True


@pytest.mark.unit
def test_wait_heartbeat_rejects_none_age() -> None:
    """Ready fence: None age is never healthy."""
    session = MagicMock()
    session.ns_name = "bs-p-wait"
    session.bridge.heartbeat_age.return_value = None
    svc = ProbeBatchService(BatchProbeConfig(backend="lua_bridge"), MagicMock())
    with patch(
        "blockchecks.service.lua_bridge_ipc.time.monotonic",
        side_effect=[0.0, 0.0, 1.0],
    ):
        with patch("blockchecks.service.lua_bridge_ipc.time.sleep"):
            assert svc._wait_heartbeat(session, within=0.5) is False


@pytest.mark.unit
def test_wait_heartbeat_accepts_fresh_age() -> None:
    session = MagicMock()
    session.ns_name = "bs-p-wait-ok"
    session.bridge.heartbeat_age.return_value = 0.05
    svc = ProbeBatchService(BatchProbeConfig(backend="lua_bridge"), MagicMock())
    with patch("blockchecks.service.lua_bridge_ipc.time.sleep"):
        assert svc._wait_heartbeat(session, within=1.0) is True


@pytest.mark.unit
@pytest.mark.asyncio(loop_scope="package")
async def test_reboot_daemon_waits_heartbeat_after_recycle() -> None:
    """Memory recycle must boot then wait for heartbeat before probing."""
    wait_calls = {"n": 0}

    class FakeSession:
        ns_name = "bs-p-0"

        def __init__(self, **_k) -> None:
            self.bridge = MagicMock()
            self.bridge.truncate_events = MagicMock()
            self.bridge.heartbeat_age = MagicMock(return_value=0.0)
            self.bridge.publish = MagicMock()
            self.bridge.drain_events = MagicMock(return_value=[])

        def boot(self) -> float:
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
                return [(99, "rss high")]
            return []

        def clear(self, pid=None) -> None:
            pass

    import blockchecks.service.batch_service as bp

    original_session = bp.BridgeSession
    original_wait = bp.ProbeBatchService._wait_heartbeat
    bp.BridgeSession = FakeSession
    real_bridge_probe = bp.run_tcp_check_bridge
    bp.run_tcp_check_bridge = lambda *a, **k: {
        "success": True,
        "bridge_applied": True,
        "bridge_events": ["APPLIED"],
    }

    def counting_wait(self, session, within=1.2):
        wait_calls["n"] += 1
        return original_wait(self, session, within=within)

    bp.ProbeBatchService._wait_heartbeat = counting_wait
    try:
        deps = _minimal_deps()
        svc = ProbeBatchService(
            BatchProbeConfig(backend="lua_bridge"), deps, memory_monitor=FakeMonitor()
        )
        ctx = BatchContext(
            ns_name="",
            items=[_item("a")],
            domain="discord.com",
            batch_id=6,
        )
        await svc.run_batch(ctx, 5.0)
        # initial fence wait + recycle reboot wait (at least one post-boot wait)
        assert wait_calls["n"] >= 2
    finally:
        bp.ProbeBatchService._wait_heartbeat = original_wait
        bp.run_tcp_check_bridge = real_bridge_probe
        bp.BridgeSession = original_session


@pytest.mark.unit
@pytest.mark.asyncio(loop_scope="package")
async def test_run_batch_mid_stop_pads_skipped_tail() -> None:
    """Items after stop_event break are padded as stopped-before-probe."""
    import asyncio

    from blockchecks.engine.results import TcpTestResult

    stop = asyncio.Event()
    calls = {"n": 0}

    class FakeSession:
        ns_name = "bs-p-0"

        def __init__(self, **_k) -> None:
            self.bridge = MagicMock()
            self.bridge.truncate_events = MagicMock()
            self.bridge.heartbeat_age = MagicMock(return_value=0.0)
            self.bridge.publish = MagicMock()
            self.bridge.drain_events = MagicMock(return_value=[])

        def boot(self) -> float:
            return 0.1

        def shutdown(self) -> None:
            return None

    def probe(*_a, **_k):
        calls["n"] += 1
        if calls["n"] == 1:
            stop.set()
        return {
            "success": True,
            "http_code": 200,
            "bridge_applied": True,
            "bridge_events": ["APPLIED"],
        }

    import blockchecks.service.batch_service as bp

    original = bp.BridgeSession
    real_probe = bp.run_tcp_check_bridge
    bp.BridgeSession = FakeSession
    bp.run_tcp_check_bridge = probe
    try:
        deps = _minimal_deps(
            tcp_result_from_data=lambda item, domain, data: TcpTestResult(
                item=item,
                domain=domain,
                success=bool(data.get("success")),
                error=data.get("error") or "",
            ),
        )
        svc = ProbeBatchService(BatchProbeConfig(backend="lua_bridge"), deps)
        ctx = BatchContext(
            ns_name="",
            items=[_item("a"), _item("b"), _item("c")],
            domain="discord.com",
            batch_id=2,
        )
        result = await svc.run_batch(ctx, timeout=5.0, stop_event=stop)
        assert len(result.results) == 3
        assert result.results[0].success is True
        assert result.results[1].error == STOPPED_BEFORE_PROBE
        assert result.results[2].error == STOPPED_BEFORE_PROBE
    finally:
        bp.run_tcp_check_bridge = real_probe
        bp.BridgeSession = original
