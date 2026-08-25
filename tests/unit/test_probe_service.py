"""Unit tests for the resident probe service + Unix-socket server."""

from __future__ import annotations

import asyncio

import pytest

from blockchecks.service.probe_service import (
    ProbeRequest,
    ProbeResult,
    ProbeService,
    classify_fail_phase,
)
from blockchecks.service.server import ProbeServer


@pytest.mark.unit
def test_classify_fail_phase_maps_errors():
    assert classify_fail_phase("curl: (28) Connection timed out") == "connect_timeout"
    assert classify_fail_phase("curl: (35) Recv failure: Connection reset") == "tls_rst_at_sni"
    assert classify_fail_phase("curl: (6) Could not resolve host") == "dns_resolve"
    assert classify_fail_phase("suspicious redirect 301 to https://x.com") == "http_redirect"
    assert classify_fail_phase("", 403) == "pass"
    assert classify_fail_phase("") == "unknown"
    # Phase 3 stream-stall taxonomy
    assert classify_fail_phase("stalled at 16kb") == "data_stall_16k"
    assert classify_fail_phase("stalled at 42kb") == "data_stall_42k"
    assert classify_fail_phase("zero window advertised") == "zero_window_stall"
    assert classify_fail_phase("HTTP/2 stream reset by RST_STREAM") == "h2_rst_stream"
    assert classify_fail_phase("TLS fatal alert received") == "tls_injected_alert"


@pytest.mark.unit
def test_probe_result_from_tcp_result():
    from blockchecks.engine.generators.base import StrategyItem
    from blockchecks.engine.results import TcpTestResult

    item = StrategyItem(label="s1", strategy="fake:repeats=6")
    r = TcpTestResult(
        item=item,
        domain="discord.com",
        success=False,
        error="curl: (28) Connection timed out",
    )
    pr = ProbeResult.from_tcp_result(r)
    assert pr.status == "FAIL"
    assert pr.fail_phase == "connect_timeout"
    assert pr.to_dict()["domain"] == "discord.com"
    assert pr.to_dict()["strategy_id"] == "s1"


@pytest.mark.unit
def test_probe_service_rejects_when_campaign_active(monkeypatch):
    import blockchecks.service.probe_service as ps

    class FakeInfo:
        pid = 99999
        command = "full"
        started_at = ""
        db_path = None
        cwd = None
        argv = []

    monkeypatch.setattr(ps, "read_active_run", lambda: FakeInfo())
    svc = ProbeService(pool_size=2)
    # busy() reflects the campaign
    assert svc.busy() == "full"
    # probe() short-circuits to busy envelope without starting pool
    resp = asyncio.run(svc.probe(ProbeRequest(domains=["a.com"], strategies=["fake:repeats=6"])))
    assert resp["status"] == "busy"
    assert resp["reason"] == "campaign_active"
    assert svc.started is False


@pytest.mark.unit
def test_probe_service_free_when_no_campaign(monkeypatch):
    import blockchecks.service.probe_service as ps

    monkeypatch.setattr(ps, "read_active_run", lambda: None)
    svc = ProbeService(pool_size=2)
    assert svc.busy() is None


@pytest.mark.unit
def test_server_handles_probe_request(monkeypatch):
    svc = ProbeService(pool_size=2)
    server = ProbeServer(svc, socket_path="/tmp/bs_test.sock")

    async def fake_probe(req: ProbeRequest):
        return {"status": "ok", "results": [{"domain": "a.com", "status": "PASS"}]}

    svc.probe = fake_probe  # type: ignore[method-assign]

    async def run():
        resp = await server.handle_request(
            {"cmd": "probe", "domains": ["a.com"], "strategies": ["fake:repeats=6"]}
        )
        assert resp["status"] == "ok"
        status = await server.handle_request({"cmd": "status"})
        assert "pool_size" in status
        unknown = await server.handle_request({"cmd": "nope"})
        assert unknown["status"] == "error"

    asyncio.run(run())


@pytest.mark.unit
def test_server_http_status_endpoint(monkeypatch):
    import blockchecks.service.probe_service as ps

    monkeypatch.setattr(ps, "read_active_run", lambda: None)
    svc = ProbeService(pool_size=2)
    server = ProbeServer(svc, socket_path="/tmp/bs_test2.sock")

    async def run():
        resp = await server._handle_status()
        assert resp["status"] == "ok"
        assert resp["pool_size"] == 2
        assert resp["started"] is False

    asyncio.run(run())


@pytest.mark.unit
def test_server_http_busy_returns_423(monkeypatch):
    import blockchecks.service.probe_service as ps

    class FakeInfo:
        pid = 99999
        command = "series_B"
        started_at = ""
        db_path = None
        cwd = None
        argv = []

    monkeypatch.setattr(ps, "read_active_run", lambda: FakeInfo())
    svc = ProbeService(pool_size=2)
    server = ProbeServer(svc, socket_path="/tmp/bs_test3.sock")

    async def run():
        resp = await server.handle_request(
            {"cmd": "probe", "domains": ["a.com"], "strategies": ["fake:repeats=6"]}
        )
        assert resp["status"] == "busy"
        assert resp["reason"] == "campaign_active"
        assert resp["active_run"] == "series_B"

    asyncio.run(run())


@pytest.mark.unit
def test_server_stop_ok_envelope():
    svc = ProbeService(pool_size=2)
    server = ProbeServer(svc, socket_path="/tmp/bs_test_stop.sock")

    async def run():
        resp = await server.handle_request({"cmd": "stop"})
        assert resp["ok"] is True
        assert resp["status"] == "ok"
        assert resp["action_status"] == "stopping"
        assert resp.get("error") is None
        assert server._stop.is_set()

    asyncio.run(run())


@pytest.mark.unit
def test_find_strategy_populates_top_strategies(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, MagicMock, patch

    import blockchecks.service.probe_service as ps
    from blockchecks.engine.generators.base import StrategyItem
    from blockchecks.engine.results import TcpTestResult

    monkeypatch.setattr(ps, "read_active_run", lambda: None)
    svc = ProbeService(pool_size=2)
    svc.started = True
    item = StrategyItem(label="s1", strategy="fake:blob=stun")
    passed = TcpTestResult(item=item, domain="a.com", success=True, http_code=200, latency_ms=110.0)
    runner = MagicMock()
    runner.test_tcp = AsyncMock(return_value=passed)
    runner._run_probe_batch = AsyncMock(return_value=[passed])
    runner.test_tcp_domains = AsyncMock(return_value=[passed])
    svc.runner = runner
    server = ProbeServer(svc, socket_path="/tmp/bs_test_find.sock")

    preset = tmp_path / "flowseal-fast.tls"
    preset.write_text("fake:blob=stun\n")

    captured: dict[str, int] = {}

    async def fake_bridge(r, queue, **kwargs):
        captured["workers"] = kwargs.get("workers")
        await r.test_tcp(item, "a.com")
        return SimpleNamespace(
            metrics=SimpleNamespace(jobs_run=1, jobs_passed=1, time_to_first_pass=0.4)
        )

    async def run():
        with (
            patch(
                "blockchecks.engine.preset_paths.resolve_strategy_preset",
                return_value=preset,
            ),
            patch(
                "blockchecks.engine.adaptive_runner.build_adaptive_queue",
                new=AsyncMock(return_value=(MagicMock(), 0)),
            ),
            patch(
                "blockchecks.engine.adaptive_runner.run_adaptive_tcp_bridge",
                new=fake_bridge,
            ),
        ):
            resp = await server.handle_request(
                {"cmd": "find_strategy", "domain": "a.com", "time_limit_sec": 5}
            )
        assert resp["ok"] is True
        assert resp["top_strategies"]
        assert resp["top_strategies"][0]["strategy"] == "fake:blob=stun"
        assert resp["top_strategies"][0]["success"] is True
        assert captured["workers"] == 2

    asyncio.run(run())
