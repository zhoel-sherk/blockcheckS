"""Unit tests for blockchecks.service.batch_bridge_probe."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from blockchecks.service.batch_bridge_probe import _run_quic_bridge_probe, run_tcp_check_bridge


def _session():
    bridge = MagicMock()
    bridge.truncate_events.return_value = None
    bridge.publish.return_value = None
    bridge.drain_events.return_value = [
        MagicMock(event="APPLIED", gen=1),
    ]
    s = MagicMock()
    s.ns_name = "bs-p0"
    s.bridge = bridge
    return s


@pytest.mark.unit
def test_bridge_tcp_success():
    s = _session()
    with patch(
        "blockchecks.service.batch_bridge_probe.invoke_curl_probe_worker",
        return_value={"success": True, "http_code": 200, "latency_ms": 50},
    ):
        data = run_tcp_check_bridge(
            s, 1, 1, "fake:blob=stun:repeats=6:tcp_ts=-1000", "discord.com", 5.0, "py"
        )
    assert data["success"] is True
    assert data["bridge_applied"] is True
    assert data.get("used_ip") is None  # no resolved_ip / no ips
    s.bridge.publish.assert_called_once()


@pytest.mark.unit
def test_bridge_tcp_single_ip_no_retry():
    """Bridge applies strategy by domain — retry-on-IP is dropped (single IP)."""
    s = _session()
    calls = []
    results = [{"success": True, "http_code": 200}]

    def fake_worker(*a, **k):
        calls.append(a)
        return results[len(calls) - 1]

    with patch(
        "blockchecks.service.batch_bridge_probe.invoke_curl_probe_worker",
        side_effect=fake_worker,
    ):
        data = run_tcp_check_bridge(
            s,
            1,
            1,
            "fake:blob=stun:repeats=6:tcp_ts=-1000",
            "discord.com",
            5.0,
            "py",
            resolved_ip="1.1.1.1",
            resolved_ips=["1.1.1.1", "2.2.2.2"],
        )
    assert data["success"] is True
    assert data["used_ip"] == "1.1.1.1"
    assert len(calls) == 1  # no retry-on-IP for bridge


@pytest.mark.unit
def test_bridge_quic_path():
    s = _session()
    with patch(
        "blockchecks.service.batch_bridge_probe._run_quic_bridge_probe",
        return_value={"success": True, "http_code": 0},
    ):
        data = run_tcp_check_bridge(
            s, 1, 1, "fake:blob=quic_initial:repeats=11", "discord.com", 5.0, "py", protocol="quic"
        )
    assert data["success"] is True
    assert data["bridge_gen"] == 1


@pytest.mark.unit
def test_bridge_googlevideo_err():
    s = _session()
    with patch(
        "blockchecks.service.batch_bridge_probe.prepare_googlevideo_probe",
        return_value=(MagicMock(), {"success": False, "error": "gv url unavailable"}),
    ):
        data = run_tcp_check_bridge(
            s, 1, 1, "fake:blob=stun:repeats=6:tcp_ts=-1000", "googlevideo.com", 5.0, "py"
        )
    assert data["success"] is False


@pytest.mark.unit
def test_quic_bridge_probe_ok():
    with patch(
        "subprocess.run",
        return_value=MagicMock(
            stdout='{"success": true, "http_code": 0, "latency_ms": 10, "http_version": "HTTP/3"}'
        ),
    ):
        data = _run_quic_bridge_probe("bs-p0", "py", "discord.com", 5.0, "1.2.3.4")
    assert data["success"] is True
    assert data["http_version"] == "HTTP/3"


@pytest.mark.unit
def test_quic_bridge_probe_bad_json():
    with patch(
        "subprocess.run",
        return_value=MagicMock(stdout="not json"),
    ):
        data = _run_quic_bridge_probe("bs-p0", "py", "discord.com", 5.0, None)
    assert data["success"] is False
    assert "parse" in data["error"]


def _session_rst_in(ttl: int = 70):
    from blockchecks.service.lua_bridge_ipc import BridgeEvent

    bridge = MagicMock()
    bridge.truncate_events.return_value = None
    bridge.publish.return_value = None
    bridge.drain_events.return_value = [
        BridgeEvent.from_line(
            f'{{"event": "STRATEGY_FAIL", "reason": "rst_in", "gen": 1, "ttl": {ttl}}}'
        ),
    ]
    s = MagicMock()
    s.ns_name = "bs-p0"
    s.bridge = bridge
    return s


@pytest.mark.unit
def test_bridge_rst_in_attached():
    s = _session_rst_in(ttl=70)
    with patch(
        "blockchecks.service.batch_bridge_probe.invoke_curl_probe_worker",
        return_value={"success": False, "error": "curl: (35) Recv failure"},
    ):
        data = run_tcp_check_bridge(
            s, 1, 1, "fake:blob=stun:repeats=6:tcp_ts=-1000", "discord.com", 5.0, "py"
        )
    assert data["bridge_rst_in"] is True
    assert data["bridge_rst_in_ttl"] == 70


@pytest.mark.unit
def test_bridge_event_parses_ttl():
    from blockchecks.service.lua_bridge_ipc import BridgeEvent

    ev = BridgeEvent.from_line(
        '{"event": "STRATEGY_FAIL", "reason": "rst_in", "gen": 3, "ttl": 65}'
    )
    assert ev.is_rst_in() is True
    assert ev.ttl == 65
    assert ev.gen == 3

    plain = BridgeEvent.from_line('{"event": "APPLIED", "id": 2, "gen": 3}')
    assert plain.is_rst_in() is False
    assert plain.ttl == 0
