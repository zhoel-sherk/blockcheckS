"""Unit tests for async_runner._run_tcp_check (mocked nfqws2 + curl worker)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from blockchecks.engine.async_runner import _run_tcp_check

pytestmark = pytest.mark.unit


def test_run_tcp_check_success_path():
    worker_payload = {
        "success": True,
        "http_code": 200,
        "latency_ms": 42.0,
        "content_ok": True,
    }
    sudo_cmds: list[tuple] = []

    def fake_sudo(*args):
        sudo_cmds.append(args)
        return None

    with (
        patch("blockchecks.engine.async_runner._nfqws2_daemon", return_value=0.05) as daemon,
        patch("blockchecks.engine.async_runner._sudo", side_effect=fake_sudo),
        patch(
            "blockchecks.engine.async_runner._invoke_curl_probe_worker",
            return_value=dict(worker_payload),
        ) as worker,
        patch("blockchecks.engine.async_runner.is_googlevideo_domain", return_value=False),
    ):
        data = _run_tcp_check(
            "bs-p0",
            "fake:blob=stun:repeats=6:tcp_ts=-1000",
            "discord.com",
            timeout=5.0,
            protocol="tls12",
        )

    assert data["success"] is True
    assert data["http_code"] == 200
    assert data["settle_ms"] == 50.0
    daemon.assert_called_once()
    assert daemon.call_args.args[0] == "bs-p0"
    conf_path = daemon.call_args.args[1]
    assert conf_path.endswith(".conf")
    # temp conf unlinked in finally
    assert not __import__("os").path.exists(conf_path)

    worker.assert_called_once()
    assert worker.call_args.args[0] == "bs-p0"
    payload = worker.call_args.args[2]
    assert payload["mode"] == "single"
    assert payload["request"]["domain"] == "discord.com"

    assert any(c[:4] == ("ip", "netns", "exec", "bs-p0") for c in sudo_cmds)
    ipt = [c for c in sudo_cmds if "iptables" in c]
    assert ipt
    assert "--queue-bypass" in ipt[0]
    assert "NFQUEUE" in ipt[0]


def test_run_tcp_check_worker_failure():
    with (
        patch("blockchecks.engine.async_runner._nfqws2_daemon", return_value=0.01),
        patch("blockchecks.engine.async_runner._sudo"),
        patch(
            "blockchecks.engine.async_runner._invoke_curl_probe_worker",
            return_value={
                "success": False,
                "http_code": 0,
                "error": "timeout",
                "latency_ms": 5000.0,
            },
        ),
        patch("blockchecks.engine.async_runner.is_googlevideo_domain", return_value=False),
    ):
        data = _run_tcp_check("bs-p1", "fake:repeats=6", "blocked.example", 5.0)

    assert data["success"] is False
    assert data["error"] == "timeout"
    assert data["settle_ms"] == 10.0


def test_run_tcp_check_gv_prepare_error_short_circuits():
    with (
        patch(
            "blockchecks.engine.async_runner.prepare_googlevideo_probe",
            return_value=(None, {"error": "gv_url_unavailable", "success": False}),
        ),
        patch("blockchecks.engine.async_runner.is_googlevideo_domain", return_value=True),
        patch("blockchecks.engine.async_runner._nfqws2_daemon") as daemon,
    ):
        data = _run_tcp_check("bs-p0", "fake:x", "googlevideo.com", 5.0)

    assert data["error"] == "gv_url_unavailable"
    daemon.assert_not_called()
