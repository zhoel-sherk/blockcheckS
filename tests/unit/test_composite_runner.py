"""Unit tests for composite_runner — single-netns composite config testing."""

from __future__ import annotations

import asyncio
import os
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.checkers.composite_runner import (
    _valid_domain,
    normalize_domains,
    run,
)
from blockchecks.engine.composite_runner import _wait_bridge_heartbeat

pytestmark = pytest.mark.unit


@contextmanager
def _composite_patches(*, pool, start_daemon=None, worker_data=None, get_fw=None):
    """Common mocks: pool lifecycle, LuaBridge.setup, heartbeat fence, daemon."""
    if start_daemon is None:
        start_daemon = MagicMock()
    if worker_data is None:
        worker_data = {"success": True, "http_code": 200, "latency_ms": 50, "error": ""}
    if get_fw is None:
        get_fw = MagicMock(return_value=MagicMock())

    bridge = MagicMock()
    bridge.setup = MagicMock()
    bridge.heartbeat_age = MagicMock(return_value=0.05)

    with ExitStack() as stack:
        stack.enter_context(patch("blockchecks.engine.composite_runner.NetNsPool", return_value=pool))
        stack.enter_context(patch("blockchecks.engine.composite_runner._start_pool", new=AsyncMock()))
        stack.enter_context(patch("blockchecks.engine.composite_runner._stop_pool", new=AsyncMock()))
        stack.enter_context(patch("blockchecks.engine.composite_runner.LuaBridge", return_value=bridge))
        stack.enter_context(
            patch("blockchecks.engine.composite_runner._wait_bridge_heartbeat", return_value=True)
        )
        stack.enter_context(patch("blockchecks.engine.composite_runner.start_daemon", new=start_daemon))
        stack.enter_context(
            patch(
                "blockchecks.engine.composite_runner.invoke_curl_probe_worker",
                return_value=worker_data,
            )
        )
        stack.enter_context(patch("blockchecks.engine.composite_runner.get_ns_firewall", get_fw))
        yield bridge


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
    with _composite_patches(
        pool=pool,
        worker_data={"success": False, "http_code": 0, "error": "fail"},
    ):
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
    get_fw = MagicMock(return_value=MagicMock())
    with _composite_patches(pool=pool, worker_data=data, get_fw=get_fw):
        rc = asyncio.run(run(str(conf), ["discord.com"], timeout=3.0))
    assert rc == 0
    fw = get_fw.return_value
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
        _composite_patches(pool=pool, worker_data=data),
        patch(
            "blockchecks.engine.composite_runner.start_daemon",
            side_effect=_fake_start,
        ),
        patch("blockchecks.engine.config.get_lua_init_scripts", return_value=injected),
    ):
        rc = asyncio.run(run(str(conf), ["discord.com"], timeout=3.0))

    assert rc == 0
    assert start_calls, "start_daemon was never called"
    launched = Path(start_calls[0])
    assert launched.suffix == ".conf" and launched != conf
    assert launched.name.endswith(f".composite.{os.getpid()}.conf")
    assert launched_text is not None
    assert "--lua-init=@/opt/zapret2/lua/zapret-lib.lua" in launched_text
    assert "--qnum=" in launched_text  # qnum preserved from fixture
    assert "--bind-fix4" in launched_text


def test_run_calls_lua_bridge_setup_before_daemon(tmp_path):
    """Composite must use LuaBridge.setup() (campaign ACL), not bare chmod 0777."""
    conf = tmp_path / "c.conf"
    conf.write_text("--qnum=200\n")
    pool = AsyncMock()
    pool.acquire = AsyncMock(return_value="ns1")
    pool.release = AsyncMock()
    order: list[str] = []
    bridge = MagicMock()

    def _setup() -> None:
        order.append("setup")

    bridge.setup = _setup

    def _start(ns_name: str, config_abs: str) -> None:
        order.append("start_daemon")

    with (
        _composite_patches(pool=pool, start_daemon=MagicMock(side_effect=_start)),
        patch("blockchecks.engine.composite_runner.LuaBridge", return_value=bridge),
    ):
        asyncio.run(run(str(conf), ["discord.com"], timeout=3.0))

    assert order[:2] == ["setup", "start_daemon"]


def test_run_heartbeat_fence_before_first_probe(tmp_path):
    """Bind marker then heartbeat fence must complete before firewall attach/probe."""
    conf = tmp_path / "c.conf"
    conf.write_text("--qnum=200\n")
    pool = AsyncMock()
    pool.acquire = AsyncMock(return_value="ns1")
    pool.release = AsyncMock()
    order: list[str] = []

    with (
        _composite_patches(pool=pool),
        patch(
            "blockchecks.engine.composite_runner._wait_queue_bind",
            side_effect=lambda *_a, **_k: order.append("bind") or True,
        ),
        patch(
            "blockchecks.engine.composite_runner._wait_bridge_heartbeat",
            side_effect=lambda *_a, **_k: order.append("heartbeat") or True,
        ),
        patch(
            "blockchecks.engine.composite_runner.get_ns_firewall",
            side_effect=lambda *_a, **_k: order.append("fw") or MagicMock(),
        ),
        patch(
            "blockchecks.engine.composite_runner.invoke_curl_probe_worker",
            side_effect=lambda *_a, **_k: order.append("probe") or {
                "success": True,
                "http_code": 200,
                "latency_ms": 1,
                "error": "",
            },
        ),
    ):
        asyncio.run(run(str(conf), ["discord.com"], timeout=3.0))

    assert order == ["bind", "heartbeat", "fw", "probe"]


def test_wait_bridge_heartbeat_delegates_to_batch_service() -> None:
    """_wait_bridge_heartbeat must use wait_heartbeat_fresh (None age = not ready)."""
    bridge = MagicMock()
    bridge.heartbeat_age.return_value = None
    with patch(
        "blockchecks.service.lua_bridge_ipc.time.monotonic",
        side_effect=[0.0, 0.0, 1.5],
    ):
        with patch("blockchecks.service.lua_bridge_ipc.time.sleep"):
            assert _wait_bridge_heartbeat(bridge, "ns-test", within=1.2) is False


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

    with _composite_patches(pool=pool, worker_data=data):
        rc = asyncio.run(run(str(conf), ["discord.com"], timeout=3.0))

    assert rc == 0  # marker seen → probe proceeds
