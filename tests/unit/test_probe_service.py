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
    assert classify_fail_phase("curl: (35) Recv failure: Connection reset") == "tls_handshake_reset"
    assert classify_fail_phase("curl: (6) Could not resolve host") == "dns_resolve"
    assert classify_fail_phase("suspicious redirect 301 to https://x.com") == "http_redirect"
    assert classify_fail_phase("", 403) == "http_403"
    assert classify_fail_phase("") == "unknown"


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
    resp = asyncio.run(
        svc.probe(ProbeRequest(domains=["a.com"], strategies=["fake:repeats=6"]))
    )
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
