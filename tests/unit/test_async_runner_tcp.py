"""Unit tests for async_runner._run_tcp_check (mocked nfqws2 + curl worker)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from blockchecks.engine.async_runner import _run_tcp_check, tcp_results_from_details
from blockchecks.engine.generators.base import StrategyItem

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
        patch("blockchecks.engine.in_ns_workers._nfqws2_daemon", return_value=0.05) as daemon,
        patch("blockchecks.engine.in_ns_workers._sudo", side_effect=fake_sudo),
        patch(
            "blockchecks.engine.in_ns_workers._invoke_curl_probe_worker",
            return_value=dict(worker_payload),
        ) as worker,
        patch("blockchecks.engine.in_ns_workers.is_googlevideo_domain", return_value=False),
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
        patch("blockchecks.engine.in_ns_workers._nfqws2_daemon", return_value=0.01),
        patch("blockchecks.engine.in_ns_workers._sudo"),
        patch(
            "blockchecks.engine.in_ns_workers._invoke_curl_probe_worker",
            return_value={
                "success": False,
                "http_code": 0,
                "error": "timeout",
                "latency_ms": 5000.0,
            },
        ),
        patch("blockchecks.engine.in_ns_workers.is_googlevideo_domain", return_value=False),
    ):
        data = _run_tcp_check("bs-p1", "fake:repeats=6", "blocked.example", 5.0)

    assert data["success"] is False
    assert data["error"] == "timeout"
    assert data["settle_ms"] == 10.0


def test_run_tcp_check_gv_prepare_error_short_circuits():
    with (
        patch(
            "blockchecks.engine.in_ns_workers.prepare_googlevideo_probe",
            return_value=(None, {"error": "gv_url_unavailable", "success": False}),
        ),
        patch("blockchecks.engine.in_ns_workers.is_googlevideo_domain", return_value=True),
        patch("blockchecks.engine.in_ns_workers._nfqws2_daemon") as daemon,
    ):
        data = _run_tcp_check("bs-p0", "fake:x", "googlevideo.com", 5.0)

    assert data["error"] == "gv_url_unavailable"
    daemon.assert_not_called()


def test_run_tcp_check_retry_on_next_ip():
    """First IP fails -> retry with next candidate; used_ip recorded."""
    from blockchecks.engine.async_runner import _run_tcp_check

    calls: list[str] = []

    def fake_worker(ns, py, payload, wall):
        ip = payload["request"].get("resolved_ip")
        calls.append(ip)
        if ip == "1.1.1.1":
            return {"success": False, "http_code": 0, "error": "timeout"}
        return {"success": True, "http_code": 200, "latency_ms": 50}

    with (
        patch("blockchecks.engine.in_ns_workers._nfqws2_daemon", return_value=0.05),
        patch("blockchecks.engine.in_ns_workers._sudo", return_value=None),
        patch(
            "blockchecks.engine.in_ns_workers._invoke_curl_probe_worker",
            side_effect=fake_worker,
        ),
        patch("blockchecks.engine.in_ns_workers.is_googlevideo_domain", return_value=False),
    ):
        data = _run_tcp_check(
            "bs-p0",
            "fake:blob=stun:repeats=6:tcp_ts=-1000",
            "discord.com",
            timeout=5.0,
            resolved_ip="1.1.1.1",
            resolved_ips=["1.1.1.1", "2.2.2.2"],
        )
    assert data["success"] is True
    assert data["used_ip"] == "2.2.2.2"
    assert calls == ["1.1.1.1", "2.2.2.2"]


def test_run_tcp_check_all_ips_fail():
    from blockchecks.engine.async_runner import _run_tcp_check

    with (
        patch("blockchecks.engine.in_ns_workers._nfqws2_daemon", return_value=0.05),
        patch("blockchecks.engine.in_ns_workers._sudo", return_value=None),
        patch(
            "blockchecks.engine.in_ns_workers._invoke_curl_probe_worker",
            return_value={"success": False, "http_code": 0, "error": "timeout"},
        ),
        patch("blockchecks.engine.in_ns_workers.is_googlevideo_domain", return_value=False),
    ):
        data = _run_tcp_check(
            "bs-p0",
            "fake:blob=stun:repeats=6:tcp_ts=-1000",
            "discord.com",
            timeout=5.0,
            resolved_ips=["1.1.1.1", "2.2.2.2"],
        )
    assert data["success"] is False
    assert data["used_ip"] == "2.2.2.2"  # last attempted


def test_run_tcp_check_config_path():
    """is_config copies the conf and injects extra lua-desync."""
    import os
    import tempfile

    from blockchecks.engine.async_runner import _run_tcp_check

    fd, conf = tempfile.mkstemp(suffix=".conf")
    with os.fdopen(fd, "w") as f:
        f.write("--qnum=200\n")
    try:
        with (
            patch("blockchecks.engine.in_ns_workers._nfqws2_daemon", return_value=0.05) as daemon,
            patch("blockchecks.engine.in_ns_workers._sudo", return_value=None),
            patch(
                "blockchecks.engine.in_ns_workers._invoke_curl_probe_worker",
                return_value={"success": True, "http_code": 200},
            ),
            patch("blockchecks.engine.in_ns_workers.is_googlevideo_domain", return_value=False),
        ):
            data = _run_tcp_check(
                "bs-p0",
                conf,
                "discord.com",
                timeout=5.0,
                is_config=True,
                extra_lua_desync="hostfakesplit:nofake2:repeats=1",
            )
        assert data["success"] is True
        copied = daemon.call_args.args[1]
        assert str(copied).endswith(".conf")
    finally:
        os.unlink(conf)


def test_run_quic_check_success():
    from blockchecks.engine.async_runner import _run_quic_check

    with (
        patch("blockchecks.engine.in_ns_workers._nfqws2_daemon", return_value=0.05),
        patch("blockchecks.engine.in_ns_workers._sudo", return_value=None),
        patch(
            "blockchecks.engine.in_ns_workers.sp.run",
            return_value=MagicMock(
                stdout='{"success": true, "http_code": 0, "http_version": "HTTP/3"}'
            ),
        ),
    ):
        data = _run_quic_check("bs-p0", "fake:blob=quic_initial:repeats=11", "discord.com", 5.0)
    assert data["success"] is True


def test_run_quic_check_bad_json():
    from blockchecks.engine.async_runner import _run_quic_check

    with (
        patch("blockchecks.engine.in_ns_workers._nfqws2_daemon", return_value=0.05),
        patch("blockchecks.engine.in_ns_workers._sudo", return_value=None),
        patch("blockchecks.engine.in_ns_workers.sp.run", return_value=MagicMock(stdout="oops")),
    ):
        data = _run_quic_check("bs-p0", "fake:blob=quic_initial:repeats=11", "discord.com", 5.0)
    assert data["success"] is False


def test_run_tcp_check_multi_success():
    from blockchecks.engine.async_runner import _run_tcp_check_multi

    worker_payload = {"discord.com": {"success": True, "http_code": 200}}
    with (
        patch("blockchecks.engine.in_ns_workers._nfqws2_daemon", return_value=0.05),
        patch("blockchecks.engine.in_ns_workers._sudo", return_value=None),
        patch(
            "blockchecks.engine.in_ns_workers._invoke_curl_probe_worker",
            side_effect=[worker_payload, {"success": True, "http_code": 200}],
        ),
        patch("blockchecks.engine.in_ns_workers.is_googlevideo_domain", return_value=False),
    ):
        out = _run_tcp_check_multi(
            "bs-p0", "fake:blob=stun:repeats=6:tcp_ts=-1000", ["discord.com"], 5.0
        )
    assert out["discord.com"]["success"] is True


def test_run_udp_check_success():
    from blockchecks.engine.async_runner import _run_udp_check

    with (
        patch("blockchecks.engine.in_ns_workers._nfqws2_daemon", return_value=0.05),
        patch("blockchecks.engine.in_ns_workers._sudo", return_value=None),
        patch(
            "blockchecks.engine.in_ns_workers.sp.run",
            return_value=MagicMock(
                stdout='{"success": true, "latency_ms": 30, "detail": "ok", "method": "rfc5389"}'
            ),
        ),
    ):
        data = _run_udp_check("bs-p0", "fake:blob=discord_udp:repeats=6", "35.217.5.42", 50006, 3.0)
    assert data["success"] is True


def test_tcp_result_from_data_used_ip():
    from blockchecks.engine.async_runner import AsyncTestRunner

    runner = AsyncTestRunner.__new__(AsyncTestRunner)
    item = StrategyItem(label="fake", strategy="fake:blob=stun:repeats=6")
    data = {"success": True, "http_code": 200, "used_ip": "1.2.3.4"}
    r = runner._tcp_result_from_data(item, "discord.com", data)
    assert r.used_ip == "1.2.3.4"
    assert r.success is True


def test_tcp_results_from_details_throttled():
    from blockchecks.engine.generators.base import StrategyItem as SI

    item = SI(label="fake", strategy="fake:blob=stun:repeats=6")
    out = tcp_results_from_details(
        {"fake": item}, [{"name": "fake", "status": "THROTTLED", "latency_ms": 500}], "discord.com"
    )
    assert len(out) == 1
    assert out[0].throttled is True
