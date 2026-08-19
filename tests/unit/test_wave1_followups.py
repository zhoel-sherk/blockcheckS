"""Unit tests for public curl probe API and preset path jail."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from blockchecks.checkers.curl_probe import CurlProbeRequest
from blockchecks.checkers.voice_discovery import load_token
from blockchecks.cli.presets import (
    PresetPathError,
    normalize_preset_name,
    resolve_domain_preset,
    resolve_strategy_preset,
)
from blockchecks.engine.secure_io import write_secure_text
from blockchecks.service.probe import invoke_curl_probe_worker, probe_request_dict


@pytest.mark.unit
def test_probe_request_dict_shape():
    req = CurlProbeRequest(domain="discord.com", timeout=5.0, resolved_ip="1.2.3.4")
    d = probe_request_dict(req)
    assert d["domain"] == "discord.com"
    assert d["timeout"] == 5.0
    assert d["resolved_ip"] == "1.2.3.4"
    assert "protocol" in d


@pytest.mark.unit
def test_invoke_curl_probe_worker_parses_stdout():
    payload = {"mode": "single", "request": {"domain": "x"}}
    fake = MagicMock()
    fake.communicate.return_value = (
        json.dumps({"success": True, "http_code": 200, "latency_ms": 12}),
        None,
    )
    fake.pid = 4242
    with patch("blockchecks.service.probe.sp.Popen", return_value=fake) as popen:
        out = invoke_curl_probe_worker("bs-p-0", "/usr/bin/python3", payload, 10.0)
    assert out["success"] is True
    assert out["http_code"] == 200
    cmd = popen.call_args.args[0]
    assert "blockchecks.engine.in_ns_workers" in cmd
    assert "--mode" in cmd
    assert "curl" in cmd


@pytest.mark.unit
def test_invoke_curl_probe_worker_bad_json():
    fake = MagicMock()
    fake.communicate.return_value = ("not-json", None)
    fake.pid = 4242
    with patch("blockchecks.service.probe.sp.Popen", return_value=fake):
        out = invoke_curl_probe_worker("bs-p-0", "/usr/bin/python3", {}, 10.0)
    assert out["success"] is False
    assert "parse:" in out["error"]


@pytest.mark.unit
def test_invoke_curl_probe_worker_timeout_returns_failure_dict():
    """TimeoutExpired must become a failure dict, not crash the batch."""
    import subprocess

    fake = MagicMock()
    fake.pid = 4242
    fake.communicate.side_effect = subprocess.TimeoutExpired(cmd="sudo ip netns exec", timeout=5)
    with (
        patch("blockchecks.service.probe.sp.Popen", return_value=fake),
        patch("blockchecks.service.probe.os.killpg"),
        patch("blockchecks.service.probe.os.getpgid", return_value=4242),
    ):
        out = invoke_curl_probe_worker("bs-p-0", "/usr/bin/python3", {}, 5.0)
    assert out["success"] is False
    assert "timeout" in out["error"]
    fake.wait.assert_called_once_with(timeout=5)


@pytest.mark.unit
def test_composite_imports_public_probe():
    import blockchecks.checkers.composite_runner as cr

    src = Path(cr.__file__).read_text(encoding="utf-8")
    assert "from blockchecks.service.probe import" in src
    assert "_invoke_curl_probe_worker" not in src


@pytest.mark.unit
@pytest.mark.parametrize(
    "bad",
    [
        "../etc/passwd",
        "/etc/passwd",
        "foo/bar",
        "..",
        "",
        "a" * 200,
    ],
)
def test_normalize_preset_name_rejects(bad: str):
    with pytest.raises(PresetPathError):
        normalize_preset_name(bad)


@pytest.mark.unit
def test_resolve_domain_preset_ok():
    path = resolve_domain_preset("benchmark")
    assert path.name == "benchmark.txt"
    assert path.is_file()


@pytest.mark.unit
def test_resolve_domain_preset_traversal():
    with pytest.raises(PresetPathError):
        resolve_domain_preset("../../etc/passwd")


@pytest.mark.unit
def test_resolve_strategy_preset_ok():
    path = resolve_strategy_preset("timeout-benchmark")
    assert path.suffix in {".tls", ".txt"}
    assert path.is_file()


@pytest.mark.unit
def test_load_token_refuses_world_writable(tmp_path: Path, monkeypatch):
    settings = tmp_path / "settings.ini"
    settings.write_text("[discord]\ntoken=sekret\n", encoding="utf-8")
    settings.chmod(0o666)
    monkeypatch.setattr("blockchecks.checkers.voice_discovery.DPI_TESTER_SETTINGS", str(settings))
    assert load_token() is None


@pytest.mark.unit
def test_write_secure_text_mode(tmp_path: Path):
    path = tmp_path / "tok.ini"
    write_secure_text(str(path), "[discord]\ntoken=x\n")
    assert path.is_file()
    assert (path.stat().st_mode & 0o777) == 0o600
