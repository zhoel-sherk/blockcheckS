"""Unit tests for in_ns_workers (quic/udp/multi worker functions, mocked)."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from blockchecks.engine.in_ns_workers import (
    _is_quic_dropped,
    _run_quic_check,
    _run_tcp_check_multi,
    _run_udp_check,
    ensure_udp_filter_lines,
    udp_filter_covers_port,
)


@pytest.mark.unit
def test_curl_worker_stdio_loop():
    from blockchecks.engine.in_ns_workers import _run_curl_worker_stdio_loop

    payload = {"mode": "single", "request": {"domain": "x", "timeout": 1.0}}
    with patch(
        "blockchecks.engine.in_ns_workers.run_curl_worker_payload",
        return_value={"success": True, "http_code": 200},
    ) as run_payload:
        import io

        buf = io.StringIO()
        with patch("sys.stdout", buf), patch("sys.stdin", io.StringIO("")):
            rc = _run_curl_worker_stdio_loop(json.dumps(payload))
    assert rc == 0
    run_payload.assert_called_once()
    lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["success"] is True


@pytest.mark.unit
def test_curl_worker_module_avoids_heavy_imports():
    """PERF-7: curl worker path must not pull nfqws2/conf_builder at import."""
    import importlib
    import sys

    heavy = {
        "blockchecks.service.nfqws2",
        "blockchecks.engine.conf_builder",
        "blockchecks.engine.nfqws_config",
        "blockchecks.engine.in_ns_workers",
    }
    saved = {name: sys.modules.pop(name, None) for name in heavy}
    try:
        before = set(sys.modules)
        importlib.import_module("blockchecks.engine.in_ns_workers")
        new = set(sys.modules) - before
        assert not new.intersection(heavy - {"blockchecks.engine.in_ns_workers"})
    finally:
        for name, mod in saved.items():
            if mod is not None:
                sys.modules[name] = mod
            else:
                sys.modules.pop(name, None)


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
            patch("blockchecks.service.nfqws2.start_daemon", return_value=0.05),
            patch("blockchecks.engine.nfqws_config._sudo", return_value=None),
            patch(
                "blockchecks.checkers.http3.quic_subprocess_result",
                return_value={"success": True, "http_version": "HTTP/3"},
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
        patch("blockchecks.service.nfqws2.start_daemon", return_value=0.05),
        patch("blockchecks.engine.nfqws_config._sudo", return_value=None),
        patch(
            "blockchecks.engine.in_ns_workers.prepare_googlevideo_probe",
            return_value=(MagicMock(), {"success": False, "error": "gv url unavailable"}),
        ),
        patch("blockchecks.engine.in_ns_workers.is_googlevideo_domain", return_value=True),
    ):
        out = _run_tcp_check_multi("bs-p0", "fake:x", ["googlevideo.com"], 5.0)
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
        patch("blockchecks.service.nfqws2.start_daemon", return_value=0.05),
        patch("blockchecks.engine.nfqws_config._sudo", return_value=None),
        patch(
            "blockchecks.service.probe.invoke_curl_probe_worker",
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
        patch("blockchecks.service.nfqws2.start_daemon", return_value=0.05) as daemon,
        patch("blockchecks.engine.nfqws_config._sudo", return_value=None),
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
    assert daemon.call_args.kwargs.get("min_procs") == 2


@pytest.mark.unit
def test_udp_filter_covers_voice_ports():
    assert udp_filter_covers_port("50000-50100", 50004) is True
    assert udp_filter_covers_port("50000-50100", 443) is False
    assert udp_filter_covers_port("50000-50100,3478", 3478) is True
    spec = next(
        ln.split("=", 1)[1]
        for ln in ensure_udp_filter_lines(["--qnum=201"], 50004)
        if ln.startswith("--filter-udp=")
    )
    assert udp_filter_covers_port(spec, 50004)


@pytest.mark.unit
def test_run_udp_check_dport_and_no_bypass():
    """iptables --dport is the probe port; no --queue-bypass before/after settle."""
    sudo_calls: list[tuple] = []

    def fake_sudo(*a, **k):
        sudo_calls.append(a)

    written = {}

    def fake_daemon(ns_name, config_path, kill_existing=True, **kw):
        written["text"] = Path(config_path).read_text(encoding="utf-8")
        written["min_procs"] = kw.get("min_procs")

    with (
        patch("blockchecks.service.nfqws2.start_daemon", side_effect=fake_daemon),
        patch("blockchecks.engine.nfqws_config._sudo", side_effect=fake_sudo),
        patch(
            "blockchecks.engine.in_ns_workers.sp.run",
            return_value=MagicMock(stdout='{"success": true, "latency_ms": 12}'),
        ),
    ):
        _run_udp_check(
            "bs-p0",
            "fake:blob=discord_udp:repeats=6",
            "35.217.48.152",
            50004,
            3.0,
            coexist=True,
        )
    ipt = [c for c in sudo_calls if "iptables" in c]
    assert ipt
    dport_idx = ipt[-1].index("--dport")
    assert ipt[-1][dport_idx + 1] == "50004"
    assert "--queue-bypass" not in ipt[-1]
    assert not any("-F" in c for c in sudo_calls)
    assert written["min_procs"] == 2
    assert any(
        udp_filter_covers_port(ln.split("=", 1)[1], 50004)
        for ln in written["text"].splitlines()
        if ln.startswith("--filter-udp=")
    )


@pytest.mark.unit
def test_run_udp_check_timeout_expired():
    import subprocess as sp

    with (
        patch("blockchecks.service.nfqws2.start_daemon", return_value=0.05),
        patch("blockchecks.engine.nfqws_config._sudo", return_value=None),
        patch(
            "blockchecks.engine.in_ns_workers.sp.run",
            side_effect=sp.TimeoutExpired(cmd="probe", timeout=1),
        ),
    ):
        data = _run_udp_check("bs-p0", "fake:blob=discord_udp:repeats=6", "1.2.3.4", 50006, 1.0)
    assert data["success"] is False
    assert "TimeoutExpired" in data["detail"]
