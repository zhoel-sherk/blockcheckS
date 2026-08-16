"""MCP server unit tests — fake Unix-socket daemon (no sudo, no netns).

Spins up a real ``asyncio.start_unix_server`` that answers like the
``bs serve`` ProbeServer (hybrid ``status``+``ok``/``data`` envelope) and
verifies every MCP tool/client path, error mapping, and offline validation.
"""

from __future__ import annotations

import asyncio
import json

import pytest

import blockchecks.mcp.server as mcp_server

pytest.importorskip("mcp", reason="mcp package not installed (pip install -e .[mcp,dev])")

pytestmark = pytest.mark.unit


def _ok(data: dict) -> bytes:
    return (
        json.dumps({"status": "ok", "ok": True, "data": data, "error": None, **data}) + "\n"
    ).encode()


def _err(msg: str) -> bytes:
    return (
        json.dumps({"status": "error", "ok": False, "data": {}, "error": msg}) + "\n"
    ).encode()


@pytest.fixture
async def fake_daemon(tmp_path, monkeypatch):
    """Run a fake unix-socket daemon and point the MCP client at it."""

    async def _client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            req = json.loads(line.decode())
            action = req.get("cmd") or req.get("action")
            if action == "status":
                writer.write(_ok({"pool_size": 2, "started": True, "uptime_s": 3.2}))
            elif action == "triage":
                writer.write(
                    _ok(
                        {
                            "domain": req.get("domain"),
                            "l3_status": "syn_ack",
                            "fail_phase": "pass",
                            "client_hello_len": 517,
                            "quic_blocked": True,
                            "dns_tampered": False,
                            "recommended_generators": ["quic_fake", "quic_ipfrag"],
                        }
                    )
                )
            elif action == "find_strategy":
                writer.write(
                    _ok(
                        {
                            "domain": req.get("domain"),
                            "done": 4,
                            "passed": 1,
                            "top_strategies": [
                                {"strategy": "fake:blob=stun", "success": True, "latency_ms": 110.0}
                            ],
                        }
                    )
                )
            elif action == "generate_config":
                writer.write(_ok({"config_content": "--qnum=200\n# cfg"}))
            elif action == "dbg_probe":
                writer.write(
                    _ok(
                        {
                            "results": [
                                {
                                    "status": "PASS",
                                    "http_code": 200,
                                    "latency_ms": 95.0,
                                    "bytes_read": 1234,
                                    "fail_phase": "",
                                    "error": "",
                                }
                            ]
                        }
                    )
                )
            elif action == "dbg_inspect_lua":
                writer.write(
                    _ok(
                        {
                            "events": [
                                {"event": "APPLIED", "gen": 1},
                                {"event": "STRATEGY_FAIL", "reason": "rst_in", "ttl": 55},
                            ]
                        }
                    )
                )
            elif action == "dbg_dump_pool":
                writer.write(_ok({"netns_pool": ["bs-p-0"], "nfqws2_pids": [123]}))
            elif action == "get_telemetry":
                writer.write(_ok({"active_run": None, "pool_size": 2}))
            else:
                writer.write(_err(f"unknown cmd: {action}"))
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    socket_path = tmp_path / "bs.sock"
    server = await asyncio.start_unix_server(_client, str(socket_path))
    monkeypatch.setattr(mcp_server, "DEFAULT_SOCKET_PATH", socket_path)
    yield socket_path
    server.close()
    await server.wait_closed()


async def test_get_service_status(fake_daemon):
    from blockchecks.mcp.server import get_service_status

    status = await get_service_status()
    assert status["pool_size"] == 2
    assert status["started"] is True


async def test_triage_domain(fake_daemon):
    from blockchecks.mcp.server import TriageResult, triage_domain

    result: TriageResult = await triage_domain("example.com")
    assert result.domain == "example.com"
    assert result.l3_status == "syn_ack"
    assert result.quic_blocked is True
    assert result.recommended_generators == ["quic_fake", "quic_ipfrag"]


async def test_find_working_strategy(fake_daemon):
    from blockchecks.mcp.server import ProbeResult, find_working_strategy

    results: list[ProbeResult] = await find_working_strategy("example.com", time_limit_sec=5)
    assert isinstance(results, list)
    assert results[0].strategy == "fake:blob=stun"
    assert results[0].status == "PASS"


async def test_generate_router_config(fake_daemon):
    from blockchecks.mcp.server import generate_router_config

    content = await generate_router_config("linux", ["a.com"])
    assert "--qnum=200" in content


async def test_generate_router_config_bad_target(fake_daemon):
    from blockchecks.mcp.server import generate_router_config

    with pytest.raises(ValueError, match="Invalid target_os"):
        await generate_router_config("windows", ["a.com"])


async def test_dbg_probe_raw(fake_daemon):
    from blockchecks.mcp.server import ProbeResult, dbg_probe_raw

    result: ProbeResult = await dbg_probe_raw("a.com", "fake:blob=stun")
    assert result.status == "PASS"
    assert result.http_code == 200


async def test_dbg_inspect_lua_ipc(fake_daemon):
    from blockchecks.mcp.server import LuaIpcTrace, dbg_inspect_lua_ipc

    trace: LuaIpcTrace = await dbg_inspect_lua_ipc("a.com", "fake")
    assert trace.desync_applied is True
    assert trace.rst_in_detected is True
    assert trace.rst_in_ttl == 55


async def test_dbg_dump_pool_state(fake_daemon):
    from blockchecks.mcp.server import dbg_dump_pool_state

    state = await dbg_dump_pool_state()
    assert "bs-p-0" in state["netns_pool"]
    assert state["nfqws2_pids"] == [123]


async def test_get_active_run_telemetry(fake_daemon):
    from blockchecks.mcp.server import get_active_run_telemetry

    telemetry = await get_active_run_telemetry()
    assert '"pool_size": 2' in telemetry


async def test_daemon_error_raises_runtime_error(fake_daemon, monkeypatch):
    from blockchecks.mcp.server import triage_domain

    async def _fail(*args, **kwargs):
        return {"ok": False, "error": "boom", "data": {}}

    monkeypatch.setattr(mcp_server, "_send_daemon_request", _fail)
    with pytest.raises(RuntimeError, match="Triage failed: boom"):
        await triage_domain("x.com")


async def test_daemon_socket_missing_raises(tmp_path):
    missing = tmp_path / "missing.sock"
    with pytest.raises(RuntimeError, match="Daemon socket not found"):
        await mcp_server._send_daemon_request("status", {}, timeout=5.0, socket_path=missing)


async def test_validate_strategy_syntax_empty():
    from blockchecks.mcp.server import dbg_validate_strategy_syntax

    result = await dbg_validate_strategy_syntax("")
    assert result.is_valid is False
    assert result.detected_conflicts == ["Strategy string is empty"]


async def test_validate_strategy_syntax_escapes_lt():
    from blockchecks.mcp.server import dbg_validate_strategy_syntax

    result = await dbg_validate_strategy_syntax("--dpi-desync=split2 --dpi-desync-split-pos=1<s3")
    assert result.is_valid is True
    assert "\\<" in result.escaped_conf_lines[1]


def test_get_manifest_path_resolves_dev_tree():
    from blockchecks.mcp.server import get_manifest_path

    path = get_manifest_path()
    assert path.exists()
    assert path.name == "manifest.toml"
