"""Unit tests for composite_runner — single-netns composite config testing."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.checkers.composite_runner import (
    _valid_domain,
    normalize_domains,
    run,
)

pytestmark = pytest.mark.unit


def test_valid_domain():
    assert _valid_domain("discord.com") is True
    assert _valid_domain("a") is True
    assert _valid_domain("") is False
    assert _valid_domain("x" * 253) is False
    assert _valid_domain("has space.com") is False


def test_normalize_domains_default():
    from blockchecks.checkers.composite_runner import DOMAINS

    assert normalize_domains(None) == DOMAINS
    assert normalize_domains([]) == DOMAINS


def test_normalize_domains_split_dedupe():
    assert normalize_domains(["a.com,b.com", "b.com", "  c.com "]) == [
        "a.com",
        "b.com",
        "c.com",
    ]
    assert normalize_domains(["a.com", "", "a.com"]) == ["a.com"]


def test_run_config_not_found(tmp_path):
    rc = asyncio.run(run(str(tmp_path / "missing.conf"), ["discord.com"]))
    assert rc == 1


def test_run_invalid_domain_records_fail(tmp_path):
    conf = tmp_path / "c.conf"
    conf.write_text("--qnum=200\n")
    pool = AsyncMock()
    pool.acquire = AsyncMock(return_value="ns1")
    pool.release = AsyncMock()
    with (
        patch("blockchecks.engine.composite_runner.NetNsPool", return_value=pool),
        patch("blockchecks.engine.composite_runner._start_pool", new=AsyncMock()),
        patch("blockchecks.engine.composite_runner._stop_pool", new=AsyncMock()),
        patch("blockchecks.engine.composite_runner.get_ns_firewall") as get_fw,
    ):
        get_fw.return_value = MagicMock()
        rc = asyncio.run(run(str(conf), ["not a domain", "discord.com"]))
    # invalid domain → no worker call; valid domain → worker call
    assert rc == 1  # both invalid/worker-fail → no passes


def test_run_success(tmp_path):
    conf = tmp_path / "c.conf"
    conf.write_text("--qnum=200\n")
    pool = AsyncMock()
    pool.acquire = AsyncMock(return_value="ns1")
    pool.release = AsyncMock()
    data = {"success": True, "http_code": 200, "latency_ms": 50, "error": ""}
    with (
        patch("blockchecks.engine.composite_runner.NetNsPool", return_value=pool),
        patch("blockchecks.engine.composite_runner._start_pool", new=AsyncMock()),
        patch("blockchecks.engine.composite_runner._stop_pool", new=AsyncMock()),
        patch("blockchecks.engine.composite_runner.start_daemon", new=MagicMock()),
        patch(
            "blockchecks.engine.composite_runner.invoke_curl_probe_worker",
            return_value=data,
        ),
        patch("blockchecks.engine.composite_runner.get_ns_firewall") as get_fw,
    ):
        fw = MagicMock()
        get_fw.return_value = fw
        rc = asyncio.run(run(str(conf), ["discord.com"], timeout=3.0))
    assert rc == 0
    assert fw.attach.call_count == 2
    pool.acquire.assert_awaited_once()
    pool.release.assert_awaited_once()


_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "regression_composite_minimal.conf"


def test_regression_fixture_strategy_validates():
    """The minimal composite regression fixture must be a clean nfqws2
    desync (multisplit + b4pda alias resolves) — guards the 4pda→b4pda
    blob-rename lesson and unescaped-< / broken-pos config regressions."""
    from blockchecks.engine.static_validator import validate_strategy

    assert _FIXTURE.is_file()
    text = _FIXTURE.read_text(encoding="utf-8")
    desync = next(ln for ln in text.splitlines() if ln.startswith("--lua-desync=")).split("=", 1)[1]
    result = validate_strategy(desync)
    errors = [i for i in result.issues if i.severity == "error"]
    assert not errors, [i.message for i in errors]


def test_run_minimal_fixture_injects_lua_init_and_probes(tmp_path, monkeypatch):
    """Running the minimal fixture (no --lua-init/--qnum) must not kill the
    daemon instantly: composite auto-injects lua-init + qnum into a config
    copy, then probes the domain. Regression for 'desync function does not
    exist' / 'Need queue number' daemon deaths."""
    assert _FIXTURE.is_file()
    conf = tmp_path / "minimal.conf"
    conf.write_text(_FIXTURE.read_text(encoding="utf-8"))

    logs = tmp_path / "logs"
    logs.mkdir()
    monkeypatch.setattr("blockchecks.engine.paths.RUNTIME_LOGS_DIR", logs)
    (logs / "nfqws2_out_ns1_0001.log").write_text("setting copy_packet mode\n")

    pool = AsyncMock()
    pool.acquire = AsyncMock(return_value="ns1")
    pool.release = AsyncMock()
    data = {"success": True, "http_code": 200, "latency_ms": 40, "error": ""}

    start_calls: list[str] = []
    launched_text: str | None = None

    def _fake_start(ns_name: str, config_abs: str) -> None:
        start_calls.append(config_abs)
        nonlocal launched_text
        launched_text = Path(config_abs).read_text(encoding="utf-8")

    injected = ["/opt/zapret2/lua/zapret-lib.lua", "/opt/zapret2/lua/zapret-antidpi.lua"]
    with (
        patch("blockchecks.engine.composite_runner.NetNsPool", return_value=pool),
        patch("blockchecks.engine.composite_runner._start_pool", new=AsyncMock()),
        patch("blockchecks.engine.composite_runner._stop_pool", new=AsyncMock()),
        patch(
            "blockchecks.engine.composite_runner.start_daemon",
            side_effect=_fake_start,
        ),
        patch("blockchecks.engine.config.get_lua_init_scripts", return_value=injected),
        patch(
            "blockchecks.engine.composite_runner.invoke_curl_probe_worker",
            return_value=data,
        ),
        patch("blockchecks.engine.composite_runner.get_ns_firewall") as get_fw,
    ):
        fw = MagicMock()
        get_fw.return_value = fw
        rc = asyncio.run(run(str(conf), ["discord.com"], timeout=3.0))

    assert rc == 0
    assert start_calls, "start_daemon was never called"
    launched = Path(start_calls[0])
    assert launched.suffix == ".conf" and launched != conf
    assert launched.name.endswith(f".composite.{os.getpid()}.conf")
    assert launched_text is not None
    assert "--lua-init=@/opt/zapret2/lua/zapret-lib.lua" in launched_text
    assert "--qnum=" in launched_text  # qnum preserved from fixture
    assert fw.attach.call_count == 2


def test_run_bind_marker_wait_short_circuits(tmp_path, monkeypatch):
    """composite waits for the daemon 'setting copy_packet mode' marker
    (queue actually bound) before the first probe — no false timeouts from
    the Lua-init window. The wait must NOT block forever when the marker
    never appears (deadline fallback)."""
    conf = tmp_path / "c.conf"
    conf.write_text("--qnum=200\n")
    logs = tmp_path / "logs"
    logs.mkdir()
    monkeypatch.setattr("blockchecks.engine.paths.RUNTIME_LOGS_DIR", logs)

    pool = AsyncMock()
    pool.acquire = AsyncMock(return_value="ns1")
    pool.release = AsyncMock()
    data = {"success": True, "http_code": 200, "latency_ms": 30, "error": ""}
    marker = logs / "nfqws2_out_ns1_0001.log"
    marker.write_text("binding this socket to queue '200'\nsetting copy_packet mode\n")

    with (
        patch("blockchecks.engine.composite_runner.NetNsPool", return_value=pool),
        patch("blockchecks.engine.composite_runner._start_pool", new=AsyncMock()),
        patch("blockchecks.engine.composite_runner._stop_pool", new=AsyncMock()),
        patch("blockchecks.engine.composite_runner.start_daemon", new=MagicMock()),
        patch(
            "blockchecks.engine.composite_runner.invoke_curl_probe_worker",
            return_value=data,
        ),
        patch("blockchecks.engine.composite_runner.get_ns_firewall") as get_fw,
    ):
        fw = MagicMock()
        get_fw.return_value = fw
        rc = asyncio.run(run(str(conf), ["discord.com"], timeout=3.0))

    assert rc == 0  # marker seen → probe proceeds
