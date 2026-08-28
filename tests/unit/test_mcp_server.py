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
    return (json.dumps({"status": "error", "ok": False, "data": {}, "error": msg}) + "\n").encode()


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
                            "voice_ok": True,
                            "udp_blocked": False,
                            "server_hops": 12,
                            "dpi_hops": 3,
                            "autottl_delta": 3,
                            "ech_blocked": False,
                            "http_blocked": False,
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
            elif action == "set_debug":
                writer.write(
                    _ok({"enabled": bool(req.get("enabled", True)), "python_level": "DEBUG"})
                )
            elif action == "log_tail":
                writer.write(
                    _ok(
                        {
                            "source": req.get("source") or "python",
                            "path": "/tmp/blockchecks.log",
                            "lines": ["hello"],
                            "offset": 5,
                            "truncated": False,
                        }
                    )
                )
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
    assert result.voice_ok is True
    assert result.udp_blocked is False
    assert result.server_hops == 12
    assert result.dpi_hops == 3
    assert result.autottl_delta == 3
    assert result.ech_blocked is False
    assert result.http_blocked is False


async def test_triage_domain_timeout_120(monkeypatch):
    import inspect

    from blockchecks.mcp.server import triage_domain

    assert "timeout=120" in inspect.getsource(triage_domain)


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


async def test_set_debug_mode_tool(fake_daemon):
    from blockchecks.mcp.server import set_debug_mode

    st = await set_debug_mode(True)
    assert st["enabled"] is True
    assert st["python_level"] == "DEBUG"


async def test_get_log_tail_from_disk(tmp_path, monkeypatch):
    from blockchecks.engine import log as logmod
    from blockchecks.mcp.server import get_log_tail

    log_file = tmp_path / "blockchecks.log"
    log_file.write_text("alpha\nbeta\n")
    monkeypatch.setattr(logmod, "python_log_path", lambda: log_file)
    result = await get_log_tail(source="python", tail=10, offset=0)
    assert result["ok"] is True
    assert result["lines"] == ["alpha", "beta"]
    assert result["offset"] == log_file.stat().st_size


async def test_get_log_tail_rejects_unknown_source():
    from blockchecks.mcp.server import get_log_tail

    with pytest.raises(ValueError, match="invalid source"):
        await get_log_tail(source="etc_passwd")


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


async def test_validate_strategy_syntax_renames_digit_blob():
    from blockchecks.mcp.server import dbg_validate_strategy_syntax

    result = await dbg_validate_strategy_syntax("fake:blob=4pda:repeats=6:tcp_ts=-1000")
    assert result.is_valid is True
    assert any("b4pda" in line for line in result.escaped_conf_lines)
    assert not any("blob=4pda" in line for line in result.escaped_conf_lines)
    assert any("digit" in c.lower() or "4pda" in c for c in result.detected_conflicts)


def test_get_manifest_path_resolves_dev_tree():
    from blockchecks.mcp.server import get_manifest_path

    path = get_manifest_path()
    assert path.exists()
    assert path.name == "manifest.toml"


# ── get_series_status (local, no daemon) ──────────────────────────────


def _make_active_info(db_path, cwd=".", argv=None):
    from blockchecks.service.run_control import ActiveRunInfo

    return ActiveRunInfo(
        pid=4242,
        command="full",
        started_at="2026-08-16T15:31:00+00:00",
        db_path=str(db_path),
        cwd=cwd,
        argv=argv or ["full", "--db", str(db_path), "--parallel", "4"],
    )


def _make_state_db(path):
    import sqlite3

    con = sqlite3.connect(str(path))
    con.execute(
        "CREATE TABLE tcp_results (id INTEGER PRIMARY KEY, strategy_id TEXT, "
        "domain TEXT, status TEXT, http_code INTEGER, latency_ms REAL, "
        "gateway_ws_ms REAL, content_valid INTEGER, read_rate_bps REAL, "
        "error TEXT, timestamp TEXT, resolved_ip TEXT, dns_verdict TEXT, "
        "doh_server TEXT, bridge_batch_id INTEGER, bridge_gen INTEGER, fail_phase TEXT)"
    )
    con.executemany(
        "INSERT INTO tcp_results (domain, status, fail_phase, timestamp) VALUES (?,?,?,?)",
        [
            ("a.com", "PASS", "", "2026-08-16T15:00:00"),
            ("b.com", "FAIL", "connect_timeout", "2026-08-16T15:00:01"),
            ("c.com", "FAIL", "connect_timeout", "2026-08-16T15:00:02"),
            ("d.com", "FAIL", "http_redirect", "2026-08-16T15:00:03"),
        ],
    )
    con.commit()
    con.close()


def _patch_run_control(monkeypatch, info):
    import blockchecks.mcp.server as ms
    import blockchecks.service.run_control as rc

    monkeypatch.setattr(rc, "read_active_run", lambda: info)
    monkeypatch.setattr(ms, "_latest_run_logpath", lambda info: None)


async def test_get_series_status_active(tmp_path, monkeypatch):
    db = tmp_path / "run_A_base.db"
    _make_state_db(db)
    from blockchecks.mcp.server import get_series_status

    info = _make_active_info(
        db, cwd=str(tmp_path), argv=["full", "--db", str(db), "--parallel", "4"]
    )
    _patch_run_control(monkeypatch, info)

    result = await get_series_status()
    assert result["active"] is True
    assert result["running"] == "full"
    assert result["pid"] == 4242
    assert result["tcp_total"] == 4
    assert result["tcp_pass"] == 1
    assert result["top_fail_phases"].get("connect_timeout") == 2
    assert result["backend"] == "lua_bridge"


async def test_get_series_status_inactive(monkeypatch):
    from blockchecks.mcp.server import get_series_status

    _patch_run_control(monkeypatch, None)
    result = await get_series_status()
    assert result == {"active": False, "running": None}


async def test_get_series_status_classic_backend(tmp_path, monkeypatch):
    db = tmp_path / "run_D_classic.db"
    _make_state_db(db)
    from blockchecks.mcp.server import get_series_status

    info = _make_active_info(
        db,
        cwd=str(tmp_path),
        argv=["full", "--db", str(db), "--classic", "--scan-level", "full"],
    )
    _patch_run_control(monkeypatch, info)

    result = await get_series_status()
    assert result["backend"] == "lua_bridge"
    assert result["scan_level"] == "full"


async def test_get_series_status_progress_line(tmp_path, monkeypatch):
    db = tmp_path / "run_B_new.db"
    _make_state_db(db)
    logs = tmp_path / "logs"
    logs.mkdir()
    logfile = logs / "run_B_20260816_183059.log"
    logfile.write_text("  [850/412212] pass=104 skip=0 1.76/s ETA 3903m\n")
    from blockchecks.mcp.server import get_series_status

    info = _make_active_info(db, cwd=str(tmp_path))
    import blockchecks.service.run_control as rc

    monkeypatch.setattr(rc, "read_active_run", lambda: info)

    result = await get_series_status()
    assert result["progress"] == "[850/412212] pass=104 skip=0 1.76/s ETA 3903m"


# ── query_strategies / get_presets / stop_campaign ────────────────────


def _make_full_db(path):
    """State db with strategies + tcp_results tables (as sqlite_store)."""
    import sqlite3

    con = sqlite3.connect(str(path))
    con.execute(
        "CREATE TABLE strategies (id INTEGER PRIMARY KEY, name TEXT, proto TEXT, flags TEXT)"
    )
    con.execute(
        "CREATE TABLE tcp_results (id INTEGER PRIMARY KEY, strategy_id INTEGER, "
        "domain TEXT, status TEXT, http_code INTEGER, latency_ms REAL, "
        "timestamp TEXT, fail_phase TEXT, probe_host TEXT DEFAULT '')"
    )
    con.executemany(
        "INSERT INTO strategies (name, proto) VALUES (?,?)",
        [
            ("std_fake_a", "tcp"),
            ("std_fake_b", "tcp"),
            ("std_fake_c", "tcp"),
        ],
    )
    con.executemany(
        "INSERT INTO tcp_results (strategy_id, domain, status, http_code, latency_ms, timestamp, fail_phase) VALUES (?,?,?,?,?,?,?)",
        [
            (1, "a.com", "PASS", 200, 80.0, "2026-08-16T10:00:00", ""),
            (2, "a.com", "PASS", 200, 120.0, "2026-08-16T10:00:01", ""),
            (3, "a.com", "FAIL", 0, 0.0, "2026-08-16T10:00:02", "connect_timeout"),
            (
                1,
                "a.com",
                "FAIL",
                0,
                0.0,
                "2026-08-16T10:00:03",
                "connect_timeout",
            ),  # later, replaces pass
        ],
    )
    con.commit()
    con.close()


async def test_query_strategies_returns_top_by_latency(tmp_path):
    db = tmp_path / "run_A_base.db"
    _make_full_db(db)
    from blockchecks.mcp.server import query_strategies

    result = await query_strategies("a.com", status="PASS", limit=10, db_path=str(db))
    assert isinstance(result, list)
    # Latest result per strategy: a→FAIL (overrides pass), b→PASS, c→FAIL.
    assert len(result) == 1
    assert result[0]["strategy"] == "std_fake_b"
    assert result[0]["status"] == "PASS"


async def test_query_strategies_pass_excludes_throttled(tmp_path):
    import sqlite3

    db = tmp_path / "throttled.db"
    con = sqlite3.connect(str(db))
    con.execute(
        "CREATE TABLE strategies (id INTEGER PRIMARY KEY, name TEXT, proto TEXT, flags TEXT)"
    )
    con.execute(
        "CREATE TABLE tcp_results (id INTEGER PRIMARY KEY, strategy_id INTEGER, "
        "domain TEXT, status TEXT, http_code INTEGER, latency_ms REAL, "
        "timestamp TEXT, fail_phase TEXT, probe_host TEXT DEFAULT '')"
    )
    con.executemany(
        "INSERT INTO strategies (name, proto) VALUES (?,?)",
        [("fast_pass", "tcp"), ("slow_throttled", "tcp")],
    )
    con.executemany(
        "INSERT INTO tcp_results (strategy_id, domain, status, http_code, latency_ms, timestamp, fail_phase) VALUES (?,?,?,?,?,?,?)",
        [
            (1, "a.com", "PASS", 200, 50.0, "2026-08-16T10:00:00", ""),
            (2, "a.com", "THROTTLED", 429, 90.0, "2026-08-16T10:00:01", ""),
        ],
    )
    con.commit()
    con.close()

    from blockchecks.mcp.server import query_strategies

    result = await query_strategies("a.com", status="PASS", limit=10, db_path=str(db))
    assert len(result) == 1
    assert result[0]["strategy"] == "fast_pass"
    assert result[0]["status"] == "PASS"


async def test_query_strategies_excludes_pass_without_applied(tmp_path):
    import sqlite3

    db = tmp_path / "applied.db"
    con = sqlite3.connect(str(db))
    con.execute(
        "CREATE TABLE strategies (id INTEGER PRIMARY KEY, name TEXT, proto TEXT, flags TEXT)"
    )
    con.execute(
        "CREATE TABLE tcp_results (id INTEGER PRIMARY KEY, strategy_id INTEGER, "
        "domain TEXT, status TEXT, http_code INTEGER, latency_ms REAL, "
        "timestamp TEXT, fail_phase TEXT, probe_host TEXT DEFAULT '', "
        "bridge_applied INTEGER)"
    )
    con.executemany(
        "INSERT INTO strategies (name, proto) VALUES (?,?)",
        [("no_apply", "tcp"), ("applied", "tcp"), ("oneshot", "tcp")],
    )
    con.executemany(
        "INSERT INTO tcp_results "
        "(strategy_id, domain, status, http_code, latency_ms, timestamp, fail_phase, bridge_applied) "
        "VALUES (?,?,?,?,?,?,?,?)",
        [
            (1, "a.com", "PASS", 200, 40.0, "2026-08-16", "", 0),
            (2, "a.com", "PASS", 200, 80.0, "2026-08-16", "", 1),
            (3, "a.com", "PASS", 200, 70.0, "2026-08-16", "", None),
        ],
    )
    con.commit()
    con.close()

    from blockchecks.mcp.server import query_strategies

    result = await query_strategies("a.com", status="PASS", limit=10, db_path=str(db))
    names = {r["strategy"] for r in result}
    assert names == {"applied", "oneshot"}


async def test_query_strategies_throttled_only(tmp_path):
    import sqlite3

    db = tmp_path / "throttled_only.db"
    con = sqlite3.connect(str(db))
    con.execute(
        "CREATE TABLE strategies (id INTEGER PRIMARY KEY, name TEXT, proto TEXT, flags TEXT)"
    )
    con.execute(
        "CREATE TABLE tcp_results (id INTEGER PRIMARY KEY, strategy_id INTEGER, "
        "domain TEXT, status TEXT, http_code INTEGER, latency_ms REAL, "
        "timestamp TEXT, fail_phase TEXT, probe_host TEXT DEFAULT '')"
    )
    con.execute("INSERT INTO strategies (name, proto) VALUES ('slow_throttled', 'tcp')")
    con.execute(
        "INSERT INTO tcp_results (strategy_id, domain, status, http_code, latency_ms, timestamp, fail_phase) VALUES (1,'a.com','THROTTLED',429,90.0,'2026-08-16','')"
    )
    con.commit()
    con.close()

    from blockchecks.mcp.server import query_strategies

    result = await query_strategies("a.com", status="THROTTLED", limit=10, db_path=str(db))
    assert len(result) == 1
    assert result[0]["status"] == "THROTTLED"


async def test_query_strategies_fail_status(tmp_path):
    db = tmp_path / "run_A_base.db"
    _make_full_db(db)
    from blockchecks.mcp.server import query_strategies

    result = await query_strategies("a.com", status="FAIL", limit=10, db_path=str(db))
    assert all(r["status"] == "FAIL" for r in result)
    assert any(r["fail_phase"] == "connect_timeout" for r in result)


async def test_query_strategies_invalid_status(tmp_path):
    db = tmp_path / "run_A_base.db"
    _make_full_db(db)
    from blockchecks.mcp.server import query_strategies

    with pytest.raises(ValueError, match="Invalid status"):
        await query_strategies("a.com", status="BOGUS", db_path=str(db))


async def test_get_presets(tmp_path, monkeypatch):
    import blockchecks.mcp.server as ms

    strat_dir = tmp_path / "presets" / "strategies"
    dom_dir = tmp_path / "presets" / "domains"
    strat_dir.mkdir(parents=True)
    dom_dir.mkdir()
    (strat_dir / "flowseal-fast.tls").write_text("s1\ns2\ns3\n")
    (strat_dir / "shortlist-tls12.tls").write_text("x\n")
    (dom_dir / "benchmark.txt").write_text("a.com\nb.com\n# comment\nc.com\n")
    (tmp_path / "presets" / "manifest.toml").write_text("[presets]\n")
    monkeypatch.setattr(ms, "PROJECT_DIR", str(tmp_path))

    strats = await ms.get_presets("strategies")
    assert {p["name"]: p["count"] for p in strats} == {
        "flowseal-fast": 3,
        "shortlist-tls12": 1,
    }
    doms = await ms.get_presets("domains")
    assert {p["name"]: p["count"] for p in doms} == {"benchmark": 3}


async def test_get_presets_invalid_kind():
    from blockchecks.mcp.server import get_presets

    with pytest.raises(ValueError, match="Invalid kind"):
        await get_presets("blobs")


async def test_stop_campaign_delegates_to_daemon(monkeypatch):
    from blockchecks.mcp import server as ms

    def fake_lock(*, force=False, wait_sec=30.0):
        return 2, "No active blockcheckS run (missing or stale run.lock)"

    async def fake_send(action, payload, timeout=30.0, socket_path=None):
        assert action == "stop"
        return {"ok": True, "error": None, "data": {"action_status": "stopping"}}

    monkeypatch.setattr("blockchecks.service.run_control.request_graceful_stop", fake_lock)
    monkeypatch.setattr(ms, "_send_daemon_request", fake_send)
    result = await ms.stop_campaign()
    assert result.get("status") == "stopping"
    assert result.get("action_status") == "stopping"
    assert result.get("ok") is True
    assert result.get("source") == "daemon"


async def test_stop_campaign_parses_legacy_stopping_envelope(monkeypatch):
    from blockchecks.mcp import server as ms

    def fake_lock(*, force=False, wait_sec=30.0):
        return 2, "No active blockcheckS run (missing or stale run.lock)"

    async def fake_send(action, payload, timeout=30.0, socket_path=None):
        return {"ok": False, "error": "cmd failed: stopping", "status": "stopping", "data": {}}

    monkeypatch.setattr("blockchecks.service.run_control.request_graceful_stop", fake_lock)
    monkeypatch.setattr(ms, "_send_daemon_request", fake_send)
    result = await ms.stop_campaign()
    assert result.get("ok") is True
    assert result.get("status") == "stopping"


async def test_stop_campaign_uses_run_lock(monkeypatch):
    from blockchecks.mcp import server as ms

    def fake_lock(*, force=False, wait_sec=30.0):
        assert force is False
        return 0, "Stopped pid 9 (full) — DB flush/export should have completed on graceful shutdown"

    async def boom(*_a, **_k):
        raise AssertionError("daemon stop must not run when run.lock is active")

    monkeypatch.setattr("blockchecks.service.run_control.request_graceful_stop", fake_lock)
    monkeypatch.setattr(ms, "_send_daemon_request", boom)
    result = await ms.stop_campaign()
    assert result["ok"] is True
    assert result["source"] == "run.lock"
    assert result["status"] == "stopped"


async def test_query_strategies_sqlite_error_returns_list(tmp_path, monkeypatch):
    import sqlite3

    db = tmp_path / "broken.db"
    db.write_bytes(b"")
    from blockchecks.mcp.server import query_strategies

    def boom(*_a, **_k):
        raise sqlite3.Error("locked")

    monkeypatch.setattr(sqlite3, "connect", boom)
    result = await query_strategies("a.com", db_path=str(db))
    assert isinstance(result, list)
    assert "cannot open" in result[0]["error"]


# ── LAYER C: zapret2 host status (read-only) ──────────────────────────


async def test_get_nfqws2_status_running(monkeypatch):
    from blockchecks.engine import preflight, system_deps

    monkeypatch.setattr(preflight, "find_host_nfqws2_pids", lambda: [111, 222])
    monkeypatch.setattr(system_deps, "resolve_nfqws2_bin", lambda: "/tmp/nfqws2")
    monkeypatch.setattr(system_deps.os.path, "isfile", lambda p: p == "/tmp/nfqws2")
    monkeypatch.setattr(system_deps, "check_nfqws2_arch", lambda p: None)

    from blockchecks.mcp.server import get_nfqws2_status

    s = await get_nfqws2_status()
    assert s["running"] is True
    assert s["pids"] == [111, 222]
    assert s["binary"] == "/tmp/nfqws2"
    assert s["arch_warning"] is None


async def test_get_nfqws2_status_not_running(monkeypatch):
    from blockchecks.engine import preflight, system_deps

    monkeypatch.setattr(preflight, "find_host_nfqws2_pids", lambda: [])
    monkeypatch.setattr(system_deps, "resolve_nfqws2_bin", lambda: None)

    from blockchecks.mcp.server import get_nfqws2_status

    s = await get_nfqws2_status()
    assert s["running"] is False
    assert s["pids"] == []
    assert s["binary"] is None


async def test_get_zapret2_config_reads_config(tmp_path, monkeypatch):
    import blockchecks.mcp.server as ms

    zap = tmp_path / "zapret2"
    zap.mkdir()
    (zap / "config").write_text("# head\nNFQWS_BASE_ARGS=--filter-tcp=443\n", encoding="utf-8")
    monkeypatch.setattr(ms, "_zapret2_dir", lambda: zap)

    c = await ms.get_zapret2_config()
    assert c["path"] == str(zap / "config")
    assert c["profile_count"] == 1
    assert "NFQWS_BASE_ARGS=--filter-tcp=443" in c["raw_lines"]


async def test_get_zapret2_config_missing_dir():
    import blockchecks.mcp.server as ms

    result = await ms.get_zapret2_config()
    # Without /opt/zapret2 on CI, must degrade gracefully.
    assert isinstance(result, dict)
    # валидный ответ: либо ошибка, либо структура с path
    assert ("error" in result) != ("path" in result), result


async def test_get_zapret2_config_rejects_traversal(tmp_path, monkeypatch):
    import blockchecks.mcp.server as ms

    zap = tmp_path / "zapret2"
    zap.mkdir()
    (zap / "config").write_text("NFQWS_BASE_ARGS=ok\n", encoding="utf-8")
    secret = tmp_path / "secret.txt"
    secret.write_text("nope\n", encoding="utf-8")
    monkeypatch.setattr(ms, "_zapret2_dir", lambda: zap)

    denied = await ms.get_zapret2_config("../secret.txt")
    assert "error" in denied
    abs_denied = await ms.get_zapret2_config(str(secret))
    assert "error" in abs_denied
    ok = await ms.get_zapret2_config("config")
    assert ok["path"] == str((zap / "config").resolve())


async def test_list_zapret2_blobs(tmp_path, monkeypatch):
    import blockchecks.mcp.server as ms

    zap = tmp_path / "zapret2"
    (zap / "blobs").mkdir(parents=True)
    (zap / "blobs" / "stun.bin").write_bytes(b"x")
    (zap / "files" / "fake").mkdir(parents=True)
    (zap / "files" / "fake" / "max_ru.bin").write_bytes(b"y")
    monkeypatch.setattr(ms, "_zapret2_dir", lambda: zap)

    blobs = await ms.list_zapret2_blobs()
    names = {b["name"] for b in blobs}
    assert "stun.bin" in names
    assert "max_ru.bin" in names
    stun = next(b for b in blobs if b["name"] == "stun.bin")
    assert stun["alias"] == "stun"


async def test_get_ipset_status_scripts(tmp_path, monkeypatch):
    import blockchecks.mcp.server as ms

    zap = tmp_path / "zapret2"
    (zap / "ipset").mkdir(parents=True)
    (zap / "ipset" / "create_ipset.sh").write_text("#!/bin/sh\n")
    monkeypatch.setattr(ms, "_zapret2_dir", lambda: zap)
    monkeypatch.setattr(ms, "subprocess_run", lambda *a, **k: None)

    s = await ms.get_ipset_status()
    assert "create_ipset.sh" in s["scripts"]
    assert isinstance(s["kernel_tables"], list)


async def test_probe_strategy_aliases_dbg_probe(monkeypatch):
    import blockchecks.mcp.server as ms

    captured = {}

    async def fake_dbg(domain, strategy, fake_blob, dry_run_db):
        captured.update(
            domain=domain, strategy=strategy, fake_blob=fake_blob, dry_run_db=dry_run_db
        )
        return ms.ProbeResult(domain=domain, strategy=strategy, status="PASS")

    monkeypatch.setattr(ms, "dbg_probe_raw", fake_dbg)
    r = await ms.probe_strategy("a.com", "fake:blob=stun")
    assert r.status == "PASS"
    assert captured["domain"] == "a.com"
    assert captured["dry_run_db"] is True


async def test_get_series_status_arbitrary_campaign_log(tmp_path, monkeypatch):
    db = tmp_path / "week_cov.db"
    _make_state_db(db)
    logs = tmp_path / "logs"
    logs.mkdir()
    logfile = logs / "week_cov_20260822_233614.log"
    logfile.write_text("  [1200/50000] pass=450 skip=0 3.12/s ETA 120m\n")
    ptr = logs / "week_cov_LATEST.logpath"
    ptr.write_text(str(logfile))

    from blockchecks.mcp.server import get_series_status

    info = _make_active_info(db, cwd=str(tmp_path), argv=["full", "--db", str(db)])
    import blockchecks.service.run_control as rc

    monkeypatch.setattr(rc, "read_active_run", lambda: info)

    result = await get_series_status()
    assert result["progress"] == "[1200/50000] pass=450 skip=0 3.12/s ETA 120m"
    assert result["domain_pass_counts"].get("a.com") == 1


def test_resolve_db_path_relative_candidate_dirs(tmp_path, monkeypatch):
    import blockchecks.mcp.server as ms

    db_dir = tmp_path / "logs"
    db_dir.mkdir()
    db_file = db_dir / "my_custom.db"
    db_file.write_bytes(b"")

    info = _make_active_info(db_file, cwd=str(tmp_path))
    import blockchecks.service.run_control as rc

    monkeypatch.setattr(rc, "read_active_run", lambda: info)

    resolved = ms._resolve_db_path("logs/my_custom.db")
    assert resolved == db_file.resolve()


async def test_query_strategies_udp(tmp_path):
    import sqlite3

    db = tmp_path / "udp_run.db"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE strategies (id INTEGER PRIMARY KEY, name TEXT, proto TEXT)")
    con.execute(
        "CREATE TABLE udp_results (id INTEGER PRIMARY KEY, strategy_id INTEGER, target TEXT, "
        "status TEXT, latency_ms REAL, error TEXT, timestamp TEXT)"
    )
    con.execute("INSERT INTO strategies VALUES (1, 'fake:blob=discord_udp:repeats=6', 'udp')")
    con.execute("INSERT INTO udp_results VALUES (1, 1, 'discord.media:50000', 'PASS', 45.0, '', '2026-08-23')")
    con.commit()
    con.close()

    from blockchecks.mcp.server import query_strategies

    res = await query_strategies("discord.media:50000", proto="udp", db_path=str(db))
    assert len(res) == 1
    assert res[0]["strategy"] == "fake:blob=discord_udp:repeats=6"
    assert res[0]["latency_ms"] == 45.0
    assert res[0]["status"] == "PASS"


async def test_get_campaign_domains_summary(tmp_path):
    import sqlite3

    db = tmp_path / "summary.db"
    con = sqlite3.connect(str(db))
    con.execute(
        "CREATE TABLE tcp_results (id INTEGER PRIMARY KEY, domain TEXT, status TEXT, latency_ms REAL)"
    )
    con.executemany(
        "INSERT INTO tcp_results (domain, status, latency_ms) VALUES (?,?,?)",
        [
            ("discord.com", "PASS", 50.0),
            ("discord.com", "PASS", 60.0),
            ("discord.com", "FAIL", 0.0),
            ("youtube.com", "FAIL", 0.0),
            ("youtube.com", "FAIL", 0.0),
        ],
    )
    con.commit()
    con.close()

    from blockchecks.mcp.server import get_campaign_domains_summary

    summary = await get_campaign_domains_summary(db_path=str(db))
    assert summary["unique_domains"] == 2
    assert summary["total_probes"] == 5
    assert summary["total_pass"] == 2
    assert summary["domains"][0]["domain"] == "discord.com"
    assert summary["domains"][0]["pass_count"] == 2
    assert summary["domains"][0]["fail_count"] == 1
    assert summary["domains"][0]["pass_rate_pct"] == 66.7
    assert summary["domains"][0]["min_pass_latency_ms"] == 50.0


async def test_generate_router_config_offline_fallback(tmp_path, monkeypatch):
    import sqlite3

    db = tmp_path / "offline.db"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE strategies (id INTEGER PRIMARY KEY, name TEXT, proto TEXT)")
    con.execute(
        "CREATE TABLE tcp_results (id INTEGER PRIMARY KEY, strategy_id INTEGER, domain TEXT, status TEXT, latency_ms REAL)"
    )
    con.execute("INSERT INTO strategies VALUES (1, 'fake:blob=stun:repeats=6:tcp_ts=-1000', 'tcp')")
    con.execute("INSERT INTO tcp_results VALUES (1, 1, 'discord.com', 'PASS', 85.0)")
    con.commit()
    con.close()

    import blockchecks.mcp.server as ms

    # Simulate daemon unreachable
    async def boom(*a, **k):
        raise ConnectionRefusedError("no daemon")

    monkeypatch.setattr(ms, "_send_daemon_request", boom)

    cfg = await ms.generate_router_config("keenetic", ["discord.com"], db_path=str(db))
    assert "fake:blob=stun:repeats=6:tcp_ts=-1000" in cfg
    assert "discord.com" in cfg


async def test_get_provider_profile(tmp_path, monkeypatch):
    import sqlite3

    from blockchecks.data_block import provider as pmod
    from blockchecks.mcp.server import get_provider_profile

    p_dir = tmp_path / "providers" / "test_isp"
    p_dir.mkdir(parents=True)
    strat_db = p_dir / "strategies.db"
    con = sqlite3.connect(str(strat_db))
    con.execute(
        "CREATE TABLE pass_strategies (id INTEGER PRIMARY KEY, strategy TEXT, domain TEXT, protocol TEXT, latency_ms REAL, http_code INTEGER, approved INTEGER, checked_at TEXT)"
    )
    con.execute(
        "INSERT INTO pass_strategies VALUES (1, 'fake:blob=stun', 'discord.com', 'tcp', 90.0, 200, 1, '2026-08-23')"
    )
    con.commit()
    con.close()

    hosts_file = p_dir / "hosts"
    hosts_file.write_text("1.1.1.1 discord.com\n")

    monkeypatch.setattr(pmod, "iter_provider_dirs", lambda **k: [p_dir])
    monkeypatch.setattr(pmod, "provider_name", lambda **k: "test_isp")
    monkeypatch.setattr(pmod, "get_provider_dir", lambda **k: p_dir)

    profile = await get_provider_profile()
    assert profile["active_provider"] == "test_isp"
    assert profile["pass_strategies_count"] == 1
    assert profile["unique_domains_covered"] == 1
    assert profile["pinned_hosts_count"] == 1
    assert len(profile["top_strategies"]) == 1



async def test_get_series_status_adaptive_default_on(tmp_path, monkeypatch):
    """AQ is ON by default: no legacy --adaptive flag needed to report True."""
    db = tmp_path / "run_W.db"
    _make_state_db(db)
    from blockchecks.mcp.server import get_series_status

    info = _make_active_info(
        db,
        cwd=str(tmp_path),
        argv=["full", "--db", str(db), "--adaptive-epsilon", "0.1"],
    )
    _patch_run_control(monkeypatch, info)

    result = await get_series_status()
    assert result["adaptive"] is True

    info_off = _make_active_info(
        db, cwd=str(tmp_path), argv=["full", "--db", str(db), "--no-adaptive"]
    )
    _patch_run_control(monkeypatch, info_off)
    result = await get_series_status()
    assert result["adaptive"] is False


def test_argv_flag_value_skips_boolean_flag():
    from blockchecks.mcp.server import _argv_flag_value

    argv = ["full", "--max", "--resume", "--db", "run.db"]
    assert _argv_flag_value(argv, "--max") is None
    assert _argv_flag_value(argv, "--db") == "run.db"


async def test_get_series_status_max_not_resume(tmp_path, monkeypatch):
    db = tmp_path / "run_resume.db"
    _make_state_db(db)
    from blockchecks.mcp.server import get_series_status

    info = _make_active_info(
        db,
        cwd=str(tmp_path),
        argv=["full", "--db", str(db), "--max", "--resume"],
    )
    _patch_run_control(monkeypatch, info)

    result = await get_series_status()
    assert "max" not in result
