"""Unit tests for sync TestRunner — single/config/udp probe paths (mocked)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from blockchecks.engine.test_runner import ScanReport, TestRunner

pytestmark = pytest.mark.unit


def _runner(**over):
    return TestRunner(**over)


def test_scan_report_passed_count():
    rep = ScanReport("d.com", "tls")
    r1 = MagicMock(success=True)
    r2 = MagicMock(success=False)
    rep.results = [r1, r2]
    assert rep.passed == 1


def test_check_tls_in_ns_error():
    from blockchecks.engine.test_runner import _check_tls_in_ns

    with patch("blockchecks.checkers.curl_probe.build_probe_request",
               return_value=(None, {"success": False, "error": "no tls"})):
        info = _check_tls_in_ns("d.com", 3.0)
    assert info["error_result"] == {"success": False, "error": "no tls"}
    assert info["payload"] is None


def test_check_tls_in_ns_ok():
    from blockchecks.engine.test_runner import _check_tls_in_ns

    req = MagicMock()
    req.domain = "d.com"
    req.timeout = 3.0
    req.resolved_ip = None
    req.resolve_name = None
    req.curl_url = None
    req.disable_ech = False
    req.googlevideo = False
    req.ggc = False
    req.protocol = "tls12"
    with patch("blockchecks.checkers.curl_probe.build_probe_request",
               return_value=(req, None)):
        info = _check_tls_in_ns("d.com", 3.0)
    assert info["payload"]["mode"] == "single"
    assert info["payload"]["request"]["domain"] == "d.com"


def test_run_check_success():
    runner = _runner()
    data = json.dumps({"success": True, "http_code": 200, "latency_ms": 50})
    with patch("blockchecks.engine.test_runner._check_tls_in_ns",
               return_value={"payload": {"request": {"domain": "d.com"}}, "error_result": None}), patch(
        "blockchecks.engine.test_runner.subprocess.run",
        return_value=MagicMock(stdout=data),
    ):
        result = runner._run_check("d.com", 3.0)
    assert result.success is True


def test_run_check_parse_error():
    runner = _runner()
    with patch("blockchecks.engine.test_runner._check_tls_in_ns",
               return_value={"payload": {}, "error_result": None}), patch(
        "blockchecks.engine.test_runner.subprocess.run",
        return_value=MagicMock(stdout="not-json"),
    ):
        result = runner._run_check("d.com", 3.0)
    assert "parse error" in result.error


def test_run_check_error_result_path():
    runner = _runner()
    with patch("blockchecks.engine.test_runner._check_tls_in_ns",
               return_value={"payload": None,
                             "error_result": {"success": False, "http_code": 0,
                                              "latency_ms": 0, "error": "boom"}}):
        result = runner._run_check("d.com", 3.0)
    assert result.error == "boom"


def test_test_single_success():
    runner = _runner()
    fw = MagicMock()
    nfq = MagicMock()
    with patch("blockchecks.engine.test_runner.Firewall", return_value=fw), patch(
        "blockchecks.engine.test_runner.Nfqws2Manager", return_value=nfq
    ), patch.object(runner, "_run_check", return_value=MagicMock(
        success=True, latency_ms=10, http_status=200, error=None
    )):
        result = runner.test_single("fake:a", "d.com", timeout=3.0)
    assert result.success is True
    fw.cleanup.assert_called_once()
    nfq.stop.assert_called_once()


def test_test_single_exception():
    runner = _runner()
    fw = MagicMock()
    nfq = MagicMock()
    nfq.start.side_effect = RuntimeError("no netns")
    with patch("blockchecks.engine.test_runner.Firewall", return_value=fw), patch(
        "blockchecks.engine.test_runner.Nfqws2Manager", return_value=nfq
    ):
        result = runner.test_single("fake:a", "d.com", timeout=3.0)
    assert "no netns" in result.error


def test_test_config():
    runner = _runner()
    fw = MagicMock()
    nfq = MagicMock()
    with patch("blockchecks.engine.test_runner.Firewall", return_value=fw), patch(
        "blockchecks.engine.test_runner.Nfqws2Manager", return_value=nfq
    ), patch.object(runner, "_run_check", return_value=MagicMock(
        success=True, latency_ms=5, http_status=200, error=None
    )):
        result = runner.test_config("/tmp/x.conf", "d.com", timeout=3.0)
    assert result.success is True
    nfq.start_config.assert_called_once_with("/tmp/x.conf")


def test_test_sequential_breaks_on_deadline():
    from blockchecks.engine.run_deadline import RunDeadline

    runner = _runner()
    with patch.object(runner, "test_single") as mock_single:
        mock_single.return_value = MagicMock(success=False, latency_ms=0,
                                             http_status=0, error=None, strategy="x")
        deadline = RunDeadline(MagicMock(), budget_sec=0.0)
        deadline._deadline = -1  # expired
        report = runner.test_sequential(["a", "b"], "d.com", deadline=deadline)
    assert report.stopped_reason == "time_limit"


def test_test_udp_config():
    runner = _runner()
    fw = MagicMock()
    nfq = MagicMock()
    with patch("blockchecks.engine.test_runner.Firewall", return_value=fw), patch(
        "blockchecks.engine.test_runner.Nfqws2Manager", return_value=nfq
    ), patch.object(runner, "_run_stun_check", return_value={
        "success": True, "latency_ms": 5, "detail": ""
    }):
        result = runner.test_udp_config("/tmp/u.conf", "1.2.3.4", port=50004, timeout=3.0)
    assert result.success is True
    fw.prepare_udp.assert_called_once()


def test_test_sequential_udp():
    runner = _runner()
    with patch.object(runner, "test_udp_config", return_value=MagicMock(
        success=False, latency_ms=0, error=None, strategy="c"
    )):
        report = runner.test_sequential_udp(["/tmp/a.conf"], "1.2.3.4", port=50004)
    assert isinstance(report, ScanReport)
    assert len(report.results) == 1


def test_run_stun_check_parse_error():
    runner = _runner()
    with patch("blockchecks.engine.test_runner.subprocess.run",
               return_value=MagicMock(stdout="garbage")):
        data = runner._run_stun_check("1.2.3.4", 50004, 3.0)
    assert data["success"] is False
    assert "parse error" in data["detail"]
