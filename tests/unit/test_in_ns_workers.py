"""Unit tests for in_ns_workers (quic/udp/multi worker functions, mocked)."""

from __future__ import annotations

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from blockchecks.engine.in_ns_workers import (
    _is_quic_dropped,
    _run_quic_check,
    _run_tcp_check_multi,
    _run_udp_check,
)


@pytest.mark.unit
def test_is_quic_dropped():
    assert _is_quic_dropped("timeout after x") is True
    assert _is_quic_dropped("Connection timed out") is True
    assert _is_quic_dropped("ngtcp2 error") is False
    assert _is_quic_dropped("") is False


@pytest.mark.unit
def test_run_quic_check_is_config():
    fd, conf = tempfile.mkstemp(suffix=".conf")
    with os.fdopen(fd, "w") as f:
        f.write("--qnum=201\n")
    try:
        with (
            patch("blockchecks.engine.in_ns_workers._nfqws2_daemon", return_value=0.05),
            patch("blockchecks.engine.in_ns_workers._sudo", return_value=None),
            patch(
                "blockchecks.engine.in_ns_workers.sp.run",
                return_value=MagicMock(stdout='{"success": true, "http_version": "HTTP/3"}'),
            ),
        ):
            data = _run_quic_check("bs-p0", conf, "discord.com", 5.0, is_config=True)
        assert data["success"] is True
    finally:
        os.unlink(conf)


@pytest.mark.unit
def test_run_tcp_check_multi_gv_fail():
    """googlevideo domain with prepare error short-circuits to gv_fail."""
    with (
        patch("blockchecks.engine.in_ns_workers._nfqws2_daemon", return_value=0.05),
        patch("blockchecks.engine.in_ns_workers._sudo", return_value=None),
        patch(
            "blockchecks.engine.in_ns_workers.prepare_googlevideo_probe",
            return_value=(MagicMock(), {"success": False, "error": "gv url unavailable"}),
        ),
        patch("blockchecks.engine.in_ns_workers.is_googlevideo_domain", return_value=True),
    ):
        out = _run_tcp_check_multi(
            "bs-p0", "fake:x", ["googlevideo.com"], 5.0
        )
    assert out["googlevideo.com"]["success"] is False


@pytest.mark.unit
def test_run_tcp_check_multi_retry():
    """Failed domain retried against next candidate IP."""
    calls = []

    def fake_worker(ns, py, payload, wall):
        # batch mode returns FAIL so per-domain retry kicks in
        if payload.get("mode") == "batch":
            return {"discord.com": {"success": False, "http_code": 0}}
        req = payload.get("request")
        ip = req.get("resolved_ip")
        calls.append(ip)
        # first candidate fails, second passes -> proves retry-on-next-IP
        return {"success": ip != "1.1.1.1", "http_code": 200}

    with (
        patch("blockchecks.engine.in_ns_workers._nfqws2_daemon", return_value=0.05),
        patch("blockchecks.engine.in_ns_workers._sudo", return_value=None),
        patch(
            "blockchecks.engine.in_ns_workers._invoke_curl_probe_worker",
            side_effect=fake_worker,
        ),
        patch("blockchecks.engine.in_ns_workers.is_googlevideo_domain", return_value=False),
    ):
        out = _run_tcp_check_multi(
            "bs-p0",
            "fake:blob=stun:repeats=6:tcp_ts=-1000",
            ["discord.com"],
            5.0,
            resolved_ip_lists={"discord.com": ["1.1.1.1", "2.2.2.2"]},
        )
    assert out["discord.com"]["success"] is True
    assert calls[-1] == "2.2.2.2"


@pytest.mark.unit
def test_run_udp_check_coexist():
    """coexist=True passes through to nfqws2 daemon (kill_existing=False)."""
    with (
        patch("blockchecks.engine.in_ns_workers._nfqws2_daemon", return_value=0.05) as daemon,
        patch("blockchecks.engine.in_ns_workers._sudo", return_value=None),
        patch(
            "blockchecks.engine.in_ns_workers.sp.run",
            return_value=MagicMock(stdout='{"success": true, "latency_ms": 30}'),
        ),
    ):
        data = _run_udp_check(
            "bs-p0", "fake:blob=discord_udp:repeats=6", "1.2.3.4", 50006, 3.0, coexist=True
        )
    assert data["success"] is True
    assert daemon.call_args.kwargs.get("kill_existing") is False
