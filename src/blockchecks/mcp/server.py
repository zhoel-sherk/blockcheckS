"""FastMCP tools over the bs serve Unix socket, plus read-only zapret2 host status."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from blockchecks.engine.config import PROJECT_DIR
from blockchecks.engine.paths import RUNTIME_LOGS_DIR, STATE_DIR

mcp = FastMCP("blockcheckS Network Orchestrator & Debugger")

# Real daemon socket: STATE_DIR/blockchecks.sock (~/.local/state/blockcheckS).
# BLOCKCHECKS_SOCKET_PATH overrides the default socket.
DEFAULT_SOCKET_PATH = Path(
    os.getenv("BLOCKCHECKS_SOCKET_PATH", str(STATE_DIR / "blockchecks.sock"))
)
DEFAULT_TIMEOUT_SEC = 30.0


def get_manifest_path() -> Path:
    """Locate presets/manifest.toml in dev tree or packaged wheel.

    PROJECT_DIR is the repo root in editable installs but can point at a
    non-repo structure after ``pip install .`` (wheel) — fall back to the
    package-relative path so the resource never 404s.
    """
    dev_path = Path(PROJECT_DIR) / "presets" / "manifest.toml"
    if dev_path.exists():
        return dev_path
    return Path(__file__).resolve().parents[2] / "presets" / "manifest.toml"


class TriageResult(BaseModel):
    domain: str
    l3_status: str = Field(description="L3 reachable, syn_ack, or icmp blocked")
    fail_phase: str = Field(
        description="Primary failure phase (e.g. TLS_RST_AT_SNI, DATA_STALL_16K, PASS)"
    )
    client_hello_len: int = Field(description="Calculated ClientHello size in bytes")
    quic_blocked: bool = Field(description="True if QUIC Initial is dropped or rejected")
    dns_tampered: bool = Field(description="True if ISP tampered with DNS responses")
    rst_at_sni: bool = Field(False, description="DPI sends RST at ClientHello SNI")
    viable_foolings: list[str] = Field(
        default_factory=list, description="Foolings that passed the viability grid"
    )
    viable_blobs: list[str] = Field(
        default_factory=list, description="Blob classes that passed the viability grid"
    )
    split_mode: str = Field("", description="Working split mode from the micro-probe")
    voice_ok: bool = Field(False, description="UDP 16KB voice path already works")
    udp_blocked: bool = Field(False, description="UDP 16KB voice burst was dropped")
    server_hops: int | None = Field(None, description="Hops to origin from SYN-ACK TTL")
    dpi_hops: int | None = Field(None, description="Hops to middlebox from RST TTL")
    autottl_delta: int | None = Field(None, description="Suggested ip_autottl delta")
    ech_blocked: bool | None = Field(None, description="True if ECH uniquely fails")
    http_blocked: bool | None = Field(None, description="True if plaintext HTTP :80 is blocked")
    recommended_generators: list[str] = Field(
        description="Strategy families recommended for this target"
    )


class ProbeResult(BaseModel):
    domain: str
    strategy: str
    status: str = Field(description="PASS, FAIL, TIMEOUT, or BLOCKED")
    http_code: int | None = None
    latency_ms: float = 0.0
    bytes_read: int = 0
    fail_phase: str | None = None
    rst_in_ttl: int | None = Field(None, description="Incoming RST packet TTL from middlebox/DPI")
    raw_error: str | None = None


class LuaIpcTrace(BaseModel):
    domain: str
    strategy: str
    events: list[dict[str, Any]] = Field(
        description="Raw events drained from scan_bridge.lua IPC stream"
    )
    desync_applied: bool = False
    rst_in_detected: bool = False
    rst_in_ttl: int = 0


class StrategySyntaxCheck(BaseModel):
    raw_strategy: str
    is_valid: bool
    parsed_tokens: list[str]
    escaped_conf_lines: list[str]
    detected_conflicts: list[str] = Field(default_factory=list)


async def _send_daemon_request(
    action: str,
    payload: dict[str, Any],
    timeout: float = DEFAULT_TIMEOUT_SEC,
    socket_path: Path | None = None,
) -> dict[str, Any]:
    """
    Sends a framed JSON-RPC request to the background `bs serve` Unix Domain Socket
    and returns the parsed response.
    """
    socket_path = Path(socket_path or DEFAULT_SOCKET_PATH)
    if not socket_path.exists():
        raise RuntimeError(
            f"Daemon socket not found at '{socket_path}'. "
            "Ensure the background service is running via 'bs serve' or systemd."
        )

    request_data = {"action": action, **payload}
    encoded_payload = json.dumps(request_data).encode("utf-8") + b"\n"

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(str(socket_path)),
            timeout=5.0,
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, FileNotFoundError) as err:
        raise RuntimeError(f"Failed to connect to blockcheckS daemon socket: {err}") from err

    try:
        writer.write(encoded_payload)
        await writer.drain()

        raw_response = await asyncio.wait_for(
            reader.readline(),
            timeout=timeout,
        )
        if not raw_response:
            raise RuntimeError("Daemon closed connection without returning data.")

        return json.loads(raw_response.decode("utf-8").strip())
    finally:
        writer.close()
        await writer.wait_closed()


@mcp.tool()
async def triage_domain(domain: str, port: int = 443) -> TriageResult:
    """
    Executes a comprehensive Preflight Triage against a target domain.
    Probes L3 connectivity, DNS integrity, TLS ClientHello sizes (Post-Quantum awareness),
    DPI RST injection phase, TCP Stream stall thresholds (7K/16K/42K), and Raw QUIC drops.
    """
    response = await _send_daemon_request("triage", {"domain": domain, "port": port}, timeout=120.0)

    if not response.get("ok"):
        raise RuntimeError(f"Triage failed: {response.get('error', 'Unknown daemon error')}")

    data = response["data"]
    return TriageResult(
        domain=domain,
        l3_status=data.get("l3_status", "UNKNOWN"),
        fail_phase=data.get("fail_phase", "UNKNOWN"),
        client_hello_len=data.get("client_hello_len", 0),
        quic_blocked=data.get("quic_blocked", False),
        dns_tampered=data.get("dns_tampered", False),
        rst_at_sni=data.get("rst_at_sni", False),
        viable_foolings=list(data.get("viable_foolings") or []),
        viable_blobs=list(data.get("viable_blobs") or []),
        split_mode=str(data.get("split_mode") or ""),
        voice_ok=bool(data.get("voice_ok", False)),
        udp_blocked=bool(data.get("udp_blocked", False)),
        server_hops=data.get("server_hops"),
        dpi_hops=data.get("dpi_hops"),
        autottl_delta=data.get("autottl_delta"),
        ech_blocked=data.get("ech_blocked"),
        http_blocked=data.get("http_blocked"),
        recommended_generators=data.get("recommended_generators", []),
    )


@mcp.tool()
async def find_working_strategy(
    domain: str,
    profile: str = "fast",
    time_limit_sec: int = 45,
) -> list[ProbeResult]:
    """
    Runs an Adaptive Queue (AQ) strategy search for the given domain using preset families.
    Returns the top functioning desync strategies with stability, latency, and throughput metrics.
    """
    response = await _send_daemon_request(
        "find_strategy",
        {"domain": domain, "profile": profile, "time_limit_sec": time_limit_sec},
        timeout=float(time_limit_sec + 15),
    )

    if not response.get("ok"):
        raise RuntimeError(f"Search failed: {response.get('error', 'Unknown daemon error')}")

    results = []
    for item in response.get("data", {}).get("top_strategies", []):
        results.append(
            ProbeResult(
                domain=domain,
                strategy=item.get("strategy", ""),
                status="PASS" if item.get("success") else "FAIL",
                http_code=item.get("http_code"),
                latency_ms=item.get("latency_ms", 0.0),
                bytes_read=item.get("bytes_read", 0),
                fail_phase=item.get("fail_phase"),
                rst_in_ttl=item.get("rst_in_ttl"),
            )
        )
    return results


@mcp.tool()
async def generate_router_config(
    target_os: str,
    domains: list[str],
    db_path: str | None = None,
) -> str:
    """
    Generates an optimized, ready-to-use routing configuration file (nfconf)
    for Keenetic, OpenWrt, or generic Linux/systemd based on the highest-scoring PASS
    strategies in the database.
    Attempts to query the running daemon first; falls back to offline generation from state.db.
    """
    valid_targets = {"keenetic", "openwrt", "linux"}
    target_clean = target_os.lower().strip()
    if target_clean not in valid_targets:
        raise ValueError(f"Invalid target_os '{target_os}'. Allowed: {', '.join(sorted(valid_targets))}")

    # Try background daemon first if socket is responsive
    try:
        response = await _send_daemon_request(
            "generate_config",
            {"target_os": target_clean, "domains": domains},
            timeout=5.0,
        )
        if response.get("ok"):
            return response.get("data", {}).get("config_content", "")
    except Exception:
        pass  # Fall back to offline generation from database

    # Offline generation
    from blockchecks.engine.conf_builder import build_keenetic_conf, build_raw_conf

    tcp_strats: list[str] = []
    udp_strats: list[str] = []

    path = _resolve_db_path(db_path)
    if path and path.is_file():
        import sqlite3

        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2.0)
            cur = con.cursor()
            tcp_rows = cur.execute(
                """SELECT s.name FROM strategies s
                   JOIN tcp_results t ON t.strategy_id = s.id
                   WHERE s.proto='tcp' AND t.status='PASS'
                   GROUP BY s.name
                   ORDER BY COUNT(DISTINCT t.domain) DESC, AVG(t.latency_ms) ASC
                   LIMIT 5"""
            ).fetchall()
            tcp_strats = [r[0] for r in tcp_rows]

            try:
                udp_rows = cur.execute(
                    """SELECT s.name FROM strategies s
                       JOIN udp_results u ON u.strategy_id = s.id
                       WHERE s.proto='udp' AND u.status='PASS'
                       GROUP BY s.name
                       ORDER BY COUNT(DISTINCT u.target) DESC, AVG(u.latency_ms) ASC
                       LIMIT 2"""
                ).fetchall()
                udp_strats = [r[0] for r in udp_rows]
            except sqlite3.Error:
                pass
            con.close()
        except sqlite3.Error:
            pass

    if not tcp_strats:
        tcp_strats = ["fake:blob=stun:repeats=6:tcp_ts=-1000"]
    if not udp_strats:
        udp_strats = ["fake:blob=discord_udp:repeats=6"]

    if target_clean == "keenetic":
        return build_keenetic_conf(
            tcp_strategies=tcp_strats, udp_strategies=udp_strats, domains=domains
        )
    return build_raw_conf(
        tcp_strategies=tcp_strats, udp_strategies=udp_strats, domains=domains
    )


@mcp.tool()
async def get_service_status() -> dict[str, Any]:
    """
    Retrieves real-time system and operational metrics from the blockcheckS service:
    netns pool occupancy, active daemon workers, memory usage, and background campaign states.
    """
    response = await _send_daemon_request("status", {}, timeout=10.0)
    if not response.get("ok"):
        raise RuntimeError(f"Status check failed: {response.get('error', 'Unknown error')}")
    return response.get("data", {})


@mcp.tool()
async def set_debug_mode(enabled: bool = True) -> dict[str, Any]:
    """Enable or disable unified debug (Python DEBUG + nfqws2 --debug=1). Requires bs serve."""
    response = await _send_daemon_request("set_debug", {"enabled": enabled}, timeout=10.0)
    if not response.get("ok"):
        raise RuntimeError(f"set_debug failed: {response.get('error', 'Unknown error')}")
    return response.get("data", {})


@mcp.tool()
async def get_log_tail(
    source: str = "python",
    tail: int = 200,
    offset: int = 0,
    raw: bool = False,
) -> dict[str, Any]:
    """Tail a labeled log channel (python / campaign / nfqws2). Campaign/python work from disk; daemon optional.

    Byte *offset* for polling. If the file rotated, *truncated* is true and offset resets.
    ANSI is stripped. nfqws2 redacts IPs unless raw=True.
    """
    from blockchecks.engine.log import LOG_SOURCES, log_tail

    if source not in LOG_SOURCES:
        raise ValueError(f"invalid source {source!r}; allowed: {sorted(LOG_SOURCES)}")
    # Disk path: works during A→F when bs serve cannot start (like get_series_status).
    return log_tail(source, tail=tail, offset=offset, raw=raw, strip_ansi=True)


@mcp.tool()
async def get_series_status() -> dict[str, Any]:
    """
    Reads the long-term campaign status directly from disk (run.lock + state.db)
    — no daemon required. Works while A→F series owns the pool (when `bs serve`
    refuses to start) and in headless runs. Read-only; never touches the DB.
    """

    from blockchecks.service.run_control import read_active_run

    info = read_active_run()
    if info is None:
        return {"active": False, "running": None}

    started = info.started_at
    uptime_h = 0.0
    try:
        from datetime import datetime

        t0 = datetime.fromisoformat(started)
        uptime_h = round((datetime.now().astimezone() - t0.astimezone()).total_seconds() / 3600, 2)
    except Exception:
        pass

    payload: dict[str, Any] = {
        "active": True,
        "running": info.command,
        "pid": info.pid,
        "started_at": started,
        "uptime_h": uptime_h,
        "db": info.db_path,
        "cwd": info.cwd,
        "argv": list(info.argv),
    }
    # Key flags for quick human glance.
    argv = list(info.argv)
    for flag, dest in (
        ("--parallel", "parallel"),
        ("--scan-level", "scan_level"),
        ("--repeats", "repeats"),
        ("--max", "max"),
    ):
        if flag in argv:
            i = argv.index(flag)
            if i + 1 < len(argv):
                payload[dest] = argv[i + 1]
    payload["backend"] = "classic" if "--classic" in argv else "lua_bridge"
    # Adaptive queue is ON by default (1.3.1+): it is disabled only by an
    # explicit --no-adaptive. The legacy "--adaptive"/"--fan-out" flags are
    # optional and their absence says nothing about the queue state.
    payload["adaptive"] = "--no-adaptive" not in argv

    # DB progress (read-only, tolerant of WAL/locks).
    db_path = info.db_path
    if db_path:
        db = Path(db_path)
        if not db.is_absolute():
            db = (Path(info.cwd or Path.cwd()) / db).resolve()
        if db.is_file():
            payload.update(_read_db_progress(db))

    # Progress line `[done/total] pass=N rate ETA` from the run log, if any.
    payload["progress"] = _read_progress_line(info)
    payload["state_dir"] = str(STATE_DIR)
    payload["logs_dir"] = str(RUNTIME_LOGS_DIR)
    from blockchecks.engine.log import debug_status

    payload["debug"] = debug_status()
    return payload


def _resolve_db_path(db_path: str | None) -> Path | None:
    """Active campaign DB from run.lock, else XDG default state.db."""
    from blockchecks.engine.config import PROJECT_DIR
    from blockchecks.engine.paths import DEFAULT_DB_PATH
    from blockchecks.service.run_control import read_active_run

    info = read_active_run()
    if db_path:
        p = Path(os.path.expanduser(db_path))
        if not p.is_absolute():
            candidate_dirs = []
            if info and info.cwd:
                candidate_dirs.append(Path(info.cwd))
            candidate_dirs.append(Path(PROJECT_DIR))
            candidate_dirs.append(Path.cwd())
            for d in candidate_dirs:
                candidate = d / p
                if candidate.exists():
                    return candidate.resolve()
            return (candidate_dirs[0] / p).resolve()
        return p
    if info and info.db_path:
        p = Path(info.db_path)
        if not p.is_absolute():
            candidate_dirs = []
            if info.cwd:
                candidate_dirs.append(Path(info.cwd))
            candidate_dirs.append(Path(PROJECT_DIR))
            candidate_dirs.append(Path.cwd())
            for d in candidate_dirs:
                candidate = d / p
                if candidate.exists():
                    return candidate.resolve()
            return (candidate_dirs[0] / p).resolve()
        return p
    return DEFAULT_DB_PATH


def _read_db_progress(db_path: Path) -> dict[str, Any]:
    """Read test counters from a state.db (read-only sqlite, never writes)."""
    import sqlite3

    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2.0)
    except sqlite3.Error:
        return {"db_error": "cannot open read-only"}
    try:
        cur = con.cursor()
        total = cur.execute("SELECT COUNT(*) FROM tcp_results").fetchone()[0]
        passed = cur.execute("SELECT COUNT(*) FROM tcp_results WHERE status='PASS'").fetchone()[0]
        rates = {}
        for phase, cnt in cur.execute(
            "SELECT fail_phase, COUNT(*) FROM tcp_results "
            "WHERE status='FAIL' AND fail_phase != '' GROUP BY fail_phase ORDER BY COUNT(*) DESC LIMIT 3"
        ).fetchall():
            rates[str(phase)] = int(cnt)

        domain_pass = {}
        for d, cnt in cur.execute(
            "SELECT domain, COUNT(*) FROM tcp_results WHERE status='PASS' GROUP BY domain ORDER BY COUNT(*) DESC LIMIT 10"
        ).fetchall():
            domain_pass[str(d)] = int(cnt)

        udp_total = 0
        udp_pass = 0
        try:
            udp_total = cur.execute("SELECT COUNT(*) FROM udp_results").fetchone()[0]
            udp_pass = cur.execute("SELECT COUNT(*) FROM udp_results WHERE status='PASS'").fetchone()[0]
        except sqlite3.Error:
            pass

        quarantined: list[dict[str, Any]] = []
        try:
            for d, reason, failed, created in cur.execute(
                "SELECT domain, reason, failed, created FROM quarantined ORDER BY created"
            ).fetchall():
                quarantined.append(
                    {
                        "domain": str(d),
                        "reason": str(reason or ""),
                        "failed": int(failed or 0),
                        "created": str(created or ""),
                    }
                )
        except sqlite3.Error:
            pass  # table absent in older campaign DBs

        res: dict[str, Any] = {
            "tcp_total": int(total),
            "tcp_pass": int(passed),
            "domain_pass_counts": domain_pass,
            "top_fail_phases": rates,
        }
        if quarantined:
            res["quarantined"] = quarantined
        if udp_total > 0:
            res["udp_total"] = int(udp_total)
            res["udp_pass"] = int(udp_pass)
        return res
    except sqlite3.Error as err:
        return {"db_error": str(err)}
    finally:
        con.close()


def _read_progress_line(info) -> str:
    """Best-effort parse of `[done/total] pass=N skip=M rate ETA` from run logs."""
    import re

    logpath = _latest_run_logpath(info)
    if not logpath:
        return ""
    try:
        lines = logpath.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    for line in reversed(lines):
        m = re.search(r"\[(\d+)/(\d+)\]\s+pass=(\d+)", line)
        if m:
            return line.strip()
    return ""


def _latest_run_logpath(info) -> Path | None:
    """Resolve the campaign's stdout log file (e.g. run_<VAR>_*.log or week_cov_*.log).

    Checks:
    1. Direct DB stem (e.g. logs/week_cov.db -> week_cov_LATEST.logpath)
    2. Variant letter if db_name starts with run_ (e.g. run_A_base.db -> run_A_LATEST.logpath)
    3. Globbing for matching log files in logs directory and XDG RUNTIME_LOGS_DIR.
    4. Fallback to campaign_log_path() from engine.log.
    """
    import glob

    from blockchecks.engine.config import PROJECT_DIR
    from blockchecks.engine.log import campaign_log_path

    db_name = str(info.db_path or "").split("/")[-1] if info.db_path else ""
    db_stem = Path(db_name).stem if db_name else ""
    variant = ""
    if db_name.startswith("run_") and "_" in db_name:
        variant = db_name.split("_", 2)[1][:1]

    cwd = Path(info.cwd or Path.cwd())
    candidate_dirs = [cwd / "logs", RUNTIME_LOGS_DIR, Path(PROJECT_DIR) / "logs", Path.cwd() / "logs"]
    seen_dirs: set[Path] = set()
    unique_dirs: list[Path] = []
    for d in candidate_dirs:
        try:
            res = d.resolve()
            if res not in seen_dirs and res.is_dir():
                seen_dirs.add(res)
                unique_dirs.append(res)
        except OSError:
            pass

    # 1. Pointers and glob patterns to check
    ptr_names = []
    if db_stem:
        ptr_names.append(f"{db_stem}_LATEST.logpath")
    if variant:
        ptr_names.append(f"run_{variant}_LATEST.logpath")

    glob_patterns = []
    if db_stem:
        glob_patterns.append(f"{db_stem}_*.log")
        glob_patterns.append(f"{db_stem}.log")
    if variant:
        glob_patterns.append(f"run_{variant}_*.log")

    for logs_dir in unique_dirs:
        # Check LATEST.logpath pointers in this directory
        for ptr_name in ptr_names:
            ptr = logs_dir / ptr_name
            if ptr.is_file():
                try:
                    target = Path(ptr.read_text(encoding="utf-8").strip())
                    if target.exists():
                        return target
                except OSError:
                    pass

        # Check glob matches for specific db_stem or variant in this directory
        for pat in glob_patterns:
            matches = sorted(
                glob.glob(str(logs_dir / pat)),
                key=lambda p: Path(p).stat().st_mtime if Path(p).is_file() else 0,
            )
            if matches:
                return Path(matches[-1])

    # 3. Fallback to generic campaign_log_path
    return campaign_log_path()


@mcp.tool()
async def query_strategies(
    domain: str,
    status: str = "PASS",
    limit: int = 20,
    proto: str = "tcp",
    db_path: str | None = None,
) -> list[dict[str, Any]]:
    """
    Returns top working strategies for a domain/target from state.db (read-only).
    Reads the latest PASS/THROTTLED result per strategy ordered by latency.
    proto: 'tcp' (default) or 'udp'.
    db_path defaults to the campaign DB from run.lock, else the XDG default.
    """
    import sqlite3

    path = _resolve_db_path(db_path)
    if path is None or not path.exists():
        return [{"error": f"state.db not found: {path}"}]

    allowed = {"PASS", "THROTTLED", "FAIL", "ALL"}
    status_key = status.upper()
    if status_key not in allowed:
        raise ValueError(f"Invalid status '{status}'. Allowed: {', '.join(sorted(allowed))}")

    proto_key = proto.lower().strip()
    if proto_key not in ("tcp", "udp"):
        raise ValueError(f"Invalid proto '{proto}'. Allowed: tcp, udp")

    statuses = (
        ("PASS", "THROTTLED") if status_key in ("PASS", "THROTTLED", "ALL") else (status_key,)
    )
    limit = max(1, min(int(limit), 100))

    def _query() -> list[dict[str, Any]]:
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2.0)
        except sqlite3.Error as err:
            return [{"error": f"cannot open {path}: {err}"}]
        try:
            cur = con.cursor()
            placeholders = ",".join("?" for _ in statuses)
            if proto_key == "tcp":
                rows = cur.execute(
                    f"""SELECT s.name, t.latency_ms, t.http_code, t.status, t.timestamp, t.fail_phase
                        FROM strategies s
                        JOIN tcp_results t ON t.strategy_id = s.id
                        WHERE s.proto='tcp' AND t.domain=? AND t.status IN ({placeholders})
                          AND t.id = (
                            SELECT t2.id FROM tcp_results t2
                            WHERE t2.strategy_id = s.id AND t2.domain=?
                            ORDER BY t2.id DESC LIMIT 1
                          )
                        ORDER BY t.latency_ms ASC
                        LIMIT ?""",
                    (domain, *statuses, domain, limit),
                )
            else:
                rows = cur.execute(
                    f"""SELECT s.name, u.latency_ms, NULL as http_code, u.status, u.timestamp, u.error as fail_phase
                        FROM strategies s
                        JOIN udp_results u ON u.strategy_id = s.id
                        WHERE s.proto='udp' AND u.target=? AND u.status IN ({placeholders})
                          AND u.id = (
                            SELECT u2.id FROM udp_results u2
                            WHERE u2.strategy_id = s.id AND u2.target=?
                            ORDER BY u2.id DESC LIMIT 1
                          )
                        ORDER BY u.latency_ms ASC
                        LIMIT ?""",
                    (domain, *statuses, domain, limit),
                )
            cols = ["strategy", "latency_ms", "http_code", "status", "timestamp", "fail_phase"]
            return [dict(zip(cols, r)) for r in rows.fetchall()]
        except sqlite3.Error as err:
            return [{"error": str(err)}]
        finally:
            con.close()

    return await asyncio.to_thread(_query)


@mcp.tool()
async def get_campaign_domains_summary(
    db_path: str | None = None,
    proto: str = "tcp",
) -> dict[str, Any]:
    """
    Returns a per-domain breakdown of tested strategies and pass counts from state.db (read-only).
    proto: 'tcp' (default) or 'udp'.
    Useful for seeing which domains have working strategies and which fail.
    """
    import sqlite3

    path = _resolve_db_path(db_path)
    if path is None or not path.exists():
        return {"error": f"state.db not found: {path}"}

    proto_key = proto.lower().strip()
    if proto_key not in ("tcp", "udp"):
        raise ValueError(f"Invalid proto '{proto}'. Allowed: tcp, udp")

    def _query() -> dict[str, Any]:
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2.0)
        except sqlite3.Error as err:
            return {"error": f"cannot open {path}: {err}"}
        try:
            cur = con.cursor()
            table = "tcp_results" if proto_key == "tcp" else "udp_results"
            target_col = "domain" if proto_key == "tcp" else "target"

            rows = cur.execute(
                f"""SELECT {target_col},
                           COUNT(*) as total_count,
                           SUM(CASE WHEN status='PASS' THEN 1 ELSE 0 END) as pass_count,
                           SUM(CASE WHEN status='FAIL' THEN 1 ELSE 0 END) as fail_count,
                           MIN(CASE WHEN status='PASS' THEN latency_ms ELSE NULL END) as min_latency,
                           AVG(CASE WHEN status='PASS' THEN latency_ms ELSE NULL END) as avg_latency
                    FROM {table}
                    GROUP BY {target_col}
                    ORDER BY pass_count DESC, total_count DESC"""
            ).fetchall()

            domains = []
            total_probes = 0
            total_pass = 0
            for r in rows:
                dom, tot, p_cnt, f_cnt, min_lat, avg_lat = r
                tot = int(tot or 0)
                p_cnt = int(p_cnt or 0)
                f_cnt = int(f_cnt or 0)
                total_probes += tot
                total_pass += p_cnt
                rate = round(p_cnt / tot * 100.0, 1) if tot > 0 else 0.0
                domains.append(
                    {
                        "domain": str(dom),
                        "total": tot,
                        "pass_count": p_cnt,
                        "fail_count": f_cnt,
                        "pass_rate_pct": rate,
                        "min_pass_latency_ms": round(min_lat, 1) if min_lat is not None else None,
                        "avg_pass_latency_ms": round(avg_lat, 1) if avg_lat is not None else None,
                    }
                )
            return {
                "db": str(path),
                "proto": proto_key,
                "unique_domains": len(domains),
                "total_probes": total_probes,
                "total_pass": total_pass,
                "domains": domains,
            }
        except sqlite3.Error as err:
            return {"error": str(err)}
        finally:
            con.close()

    return await asyncio.to_thread(_query)


@mcp.tool()
async def get_presets(kind: str = "strategies") -> list[dict[str, Any]]:
    """
    Lists available strategy or domain presets from presets/ (read-only).
    kind: 'strategies' | 'domains'. Returns name → entry count.
    """
    import glob as _glob

    kind = kind.lower()
    if kind not in ("strategies", "domains"):
        raise ValueError(f"Invalid kind '{kind}'. Allowed: strategies, domains")

    base = get_manifest_path().parent
    patterns = (
        (
            "strategies",
            [
                str(base / "strategies" / "*.tls"),
                str(base / "strategies" / "*.txt"),
                str(base / "strategies" / "*.http"),
                str(base / "strategies" / "*.quic"),
                str(base / "strategies" / "*.udp"),
            ],
        ),
        ("domains", [str(base / "domains" / "*.txt")]),
    )[0 if kind == "strategies" else 1]

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pattern in patterns[1]:
        for f in sorted(_glob.glob(pattern)):
            name = Path(f).stem
            if name in seen:
                continue
            seen.add(name)
            try:
                count = sum(
                    1
                    for line in Path(f).read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip() and not line.strip().startswith("#")
                )
            except OSError:
                count = 0
            out.append({"name": name, "kind": kind, "count": count})
    return out


@mcp.tool()
async def stop_campaign(wait: float = 30.0) -> dict[str, Any]:
    """
    Gracefully stops the active long-term campaign via the daemon socket
    (action=stop → SIGTERM → flush → export). Requires `bs serve` to be up.
    """
    response = await _send_daemon_request("stop", {}, timeout=min(wait + 5.0, 90.0))
    data = dict(response.get("data") or {})
    status = data.get("action_status") or data.get("status") or response.get("status")
    # Older clients sent status="stopping" (ok=False).
    if response.get("ok") or status == "stopping":
        resolved = status or "stopping"
        return {**data, "ok": True, "status": resolved, "action_status": resolved}
    return {
        "ok": False,
        "error": response.get("error") or "stop failed",
        "status": status or "error",
    }


@mcp.tool()
async def dbg_probe_raw(
    domain: str,
    strategy: str,
    fake_blob: str | None = None,
    dry_run_db: bool = True,
) -> ProbeResult:
    """
    Executes an isolated, single-shot strategy probe inside a dedicated ephemeral netns.
    By default (dry_run_db=True), prevents writing debug noise/results to production state.db.
    Returns exact socket timings, HTTP response codes, and DPI TTL signals.
    """
    response = await _send_daemon_request(
        "dbg_probe",
        {
            "domain": domain,
            "strategy": strategy,
            "fake_blob": fake_blob,
            "dry_run_db": dry_run_db,
        },
        timeout=20.0,
    )

    if not response.get("ok"):
        return ProbeResult(
            domain=domain,
            strategy=strategy,
            status="FAIL",
            raw_error=response.get("error", "Unknown daemon error"),
        )

    # Daemon returns the batch contract: data["results"][0] for single-shot.
    res = response.get("data", {})
    results = res.get("results") or []
    r = results[0] if results else res
    status = (
        "PASS"
        if (r.get("status") == "PASS" or r.get("success"))
        else ("TIMEOUT" if r.get("fail_phase") == "connect_timeout" else "FAIL")
    )
    return ProbeResult(
        domain=domain,
        strategy=strategy,
        status=status,
        http_code=r.get("http_code") or None,
        latency_ms=r.get("latency_ms", 0.0),
        bytes_read=r.get("bytes_read", 0),
        fail_phase=r.get("fail_phase") or None,
        rst_in_ttl=r.get("rst_in_ttl"),
        raw_error=r.get("error") or r.get("raw_error"),
    )


@mcp.tool()
async def dbg_inspect_lua_ipc(
    domain: str,
    strategy: str,
) -> LuaIpcTrace:
    """
    Executes a network probe with Lua bridge tracing active (`scan_bridge.lua`).
    Returns the real-time event timeline (APPLIED, STRATEGY_FAIL, rst_in, ttl)
    to diagnose desync phase mismatches and hardware DPI responses.
    """
    response = await _send_daemon_request(
        "dbg_inspect_lua",
        {"domain": domain, "strategy": strategy},
        timeout=20.0,
    )

    if not response.get("ok"):
        raise RuntimeError(f"Lua IPC trace failed: {response.get('error', 'Unknown error')}")

    data = response.get("data", {})
    events = data.get("events", [])
    desync_applied = any(e.get("event") == "APPLIED" for e in events)
    rst_in_events = [
        e for e in events if e.get("event") == "STRATEGY_FAIL" and e.get("reason") == "rst_in"
    ]

    return LuaIpcTrace(
        domain=domain,
        strategy=strategy,
        events=events,
        desync_applied=desync_applied,
        rst_in_detected=bool(rst_in_events),
        rst_in_ttl=max((e.get("ttl", 0) for e in rst_in_events), default=0),
    )


@mcp.tool()
async def dbg_validate_strategy_syntax(
    strategy_cli: str,
) -> StrategySyntaxCheck:
    """
    Performs an offline static validation of nfqws2 desync CLI arguments.
    Checks parameter naming, case sensitivity, conflict detection (e.g. invalid offsets,
    missing blobs, unescaped '<' symbols), and returns sanitized config lines.
    """
    from blockchecks.engine.conf_builder import escape_conf_lt, split_cli_args
    from blockchecks.engine.static_validator import validate_strategy

    # Static sanity checks without requiring network daemon.
    tokens = strategy_cli.strip().split()
    if not tokens:
        return StrategySyntaxCheck(
            raw_strategy=strategy_cli,
            is_valid=False,
            parsed_tokens=[],
            escaped_conf_lines=[],
            detected_conflicts=["Strategy string is empty"],
        )

    # Unified semantics from engine.static_validator (single source of truth).
    result = validate_strategy(strategy_cli)
    conflicts = [i.message for i in result.issues if i.severity == "error"]
    if not conflicts:
        conflicts = [i.message for i in result.issues if i.severity == "warning"]

    # Unified sanitization from conf_builder (single source of truth 1.3.1).
    escaped_lines = [escape_conf_lt(t) for t in split_cli_args(strategy_cli)]

    return StrategySyntaxCheck(
        raw_strategy=strategy_cli,
        is_valid=len(conflicts) == 0,
        parsed_tokens=tokens,
        escaped_conf_lines=escaped_lines,
        detected_conflicts=conflicts,
    )


@mcp.tool()
async def dbg_dump_pool_state() -> dict[str, Any]:
    """
    Inspects kernel and namespace states: active veth network interfaces,
    running nfqws2 PIDs, socket leak counters, and stale run_control locks.
    """
    response = await _send_daemon_request("dbg_dump_pool", {}, timeout=10.0)
    if not response.get("ok"):
        raise RuntimeError(f"Pool state dump failed: {response.get('error', 'Unknown error')}")
    return response.get("data", {})


_ZAPRET2_DIR = Path("/opt/zapret2")


def _zapret2_dir() -> Path | None:
    """Resolve zapret2 root: env ZAPRET2_ROOT → /opt/zapret2 → None."""
    env = os.getenv("ZAPRET2_ROOT", "").strip()
    if env and os.path.isdir(env):
        return Path(env)
    return _ZAPRET2_DIR if _ZAPRET2_DIR.is_dir() else None


def _canonical_under(root: Path, path: str) -> Path | None:
    """Resolve *path* under *root*; reject ``..`` and escapes."""
    if not path or ".." in Path(path).parts:
        return None
    raw = Path(path)
    candidate = raw if raw.is_absolute() else (root / raw)
    try:
        resolved = candidate.resolve()
        allowed = root.resolve()
    except OSError:
        return None
    if not resolved.is_relative_to(allowed):
        return None
    return resolved


@mcp.tool()
async def get_nfqws2_status() -> dict[str, Any]:
    """
    Reports whether nfqws2 is running on the host, which binary is resolved
    (env → which → /opt/zapret2 → vendor), and whether its ELF arch matches
    the host. Read-only; never launches or stops nfqws2.
    """
    from blockchecks.engine.preflight import find_host_nfqws2_pids
    from blockchecks.engine.system_deps import check_nfqws2_arch, resolve_nfqws2_bin

    pids = find_host_nfqws2_pids()
    binary = resolve_nfqws2_bin()
    payload: dict[str, Any] = {
        "running": bool(pids),
        "pids": pids,
        "binary": binary,
        "binary_exists": bool(binary and os.path.isfile(binary)),
    }
    if binary and os.path.isfile(binary):
        payload["arch_warning"] = check_nfqws2_arch(binary)
    else:
        payload["arch_warning"] = "nfqws2 binary not found (auto-fetch on first run)"
    return payload


@mcp.tool()
async def get_zapret2_config(path: str | None = None) -> dict[str, Any]:
    """
    Returns the active zapret2 config (default /opt/zapret2/config, else
    config.default) as lines + a lightweight profile breakdown. Read-only.
    """
    root = _zapret2_dir()
    if root is None:
        return {"error": "zapret2 dir not found (set ZAPRET2_ROOT or install /opt/zapret2)"}
    if path:
        cfg = _canonical_under(root, path)
        if cfg is None:
            return {"error": "path rejected (must stay under zapret2 dir)"}
        if not cfg.is_file():
            return {"error": f"no config at {cfg}"}
    else:
        cfg = root / "config"
        if not cfg.is_file():
            cfg = root / "config.default"
        if not cfg.is_file():
            return {"error": f"no config at {cfg} or {root / 'config.default'}"}
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError as err:
        return {"error": f"cannot read {cfg}: {err}"}
    lines = text.splitlines()
    profiles: dict[str, list[str]] = {}
    current = "default"
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("["):
            current = stripped.strip("[]").strip()
            profiles.setdefault(current, [])
        else:
            profiles.setdefault(current, []).append(stripped)
    return {
        "path": str(cfg),
        "profile_count": len(profiles),
        "profiles": profiles,
        "raw_lines": lines,
    }


@mcp.tool()
async def list_zapret2_blobs() -> list[dict[str, Any]]:
    """
    Lists blob payloads available under /opt/zapret2 (blobs/ + files/fake/)
    and their resolvability through blockcheckS aliases. Read-only.
    """
    from blockchecks.engine.blob_aliases import BLOB_ALIAS_MAP

    root = _zapret2_dir()
    if root is None:
        return [{"error": "zapret2 dir not found"}]
    out: list[dict[str, Any]] = []
    for sub in ("blobs", "files", "files/fake"):
        d = root / sub
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.bin")):
            name = p.name
            alias = next((a for a, fn in BLOB_ALIAS_MAP.items() if fn == name), None)
            out.append(
                {
                    "path": str(p),
                    "name": name,
                    "size": p.stat().st_size if p.is_file() else 0,
                    "alias": alias,
                }
            )
    return out


@mcp.tool()
async def get_ipset_status() -> dict[str, Any]:
    """
    Reports zapret2 ipset tooling: script presence under /opt/zapret2/ipset and
    live kernel ipset tables (via `ipset list -name` when available). Read-only.
    """
    root = _zapret2_dir()
    scripts: list[str] = []
    if root is not None:
        ipset_dir = root / "ipset"
        if ipset_dir.is_dir():
            scripts = sorted(p.name for p in ipset_dir.glob("*.sh"))
    tables: list[str] = []
    import shutil

    if shutil.which("ipset"):
        try:
            r = subprocess_run(["ipset", "list", "-name"], timeout=3)
            if r.returncode == 0:
                tables = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
        except Exception:
            tables = []
    return {"scripts": scripts, "kernel_tables": tables}


@mcp.tool()
async def get_provider_profile(provider: str | None = None) -> dict[str, Any]:
    """
    Inspects provider data in data_block/ (ISP name, triage.toml profile,
    DNS cache size, tampered DNS entries, pass strategies count). Read-only.
    """
    from blockchecks.data_block.provider import (
        get_provider_dir,
        iter_provider_dirs,
        provider_name,
    )
    from blockchecks.data_block.store import ProviderStore

    all_provider_dirs = iter_provider_dirs(allow_detect=False)
    all_providers = [d.name for d in all_provider_dirs]

    active_name = provider.strip() if provider else provider_name(allow_detect=False)
    p_dir = None
    for d in all_provider_dirs:
        if d.name == active_name:
            p_dir = d
            break
    if p_dir is None:
        p_dir = get_provider_dir(allow_detect=False)
        active_name = p_dir.name

    store = ProviderStore(p_dir)
    triage = store.load_triage()
    triage_data = triage.to_dict() if triage else None

    # Inspect strategies.db (read-only)
    pass_strategies_count = 0
    unique_domains_count = 0
    top_strategies: list[dict[str, Any]] = []
    if store.strategies_db.is_file():
        import sqlite3

        try:
            con = sqlite3.connect(f"file:{store.strategies_db}?mode=ro", uri=True, timeout=2.0)
            cur = con.cursor()
            pass_strategies_count = cur.execute("SELECT COUNT(*) FROM pass_strategies").fetchone()[0]
            unique_domains_count = cur.execute(
                "SELECT COUNT(DISTINCT domain) FROM pass_strategies"
            ).fetchone()[0]
            for row in cur.execute(
                """SELECT strategy, COUNT(domain) as dom_count, AVG(latency_ms) as avg_lat
                   FROM pass_strategies
                   GROUP BY strategy
                   ORDER BY dom_count DESC, avg_lat ASC
                   LIMIT 5"""
            ).fetchall():
                top_strategies.append(
                    {
                        "strategy": str(row[0]),
                        "domain_count": int(row[1]),
                        "avg_latency_ms": round(float(row[2]), 1) if row[2] else 0.0,
                    }
                )
            con.close()
        except sqlite3.Error:
            pass

    # Inspect dns.db (read-only)
    dns_records_count = 0
    dns_tampered_count = 0
    if store.dns_db.is_file():
        import sqlite3

        try:
            con = sqlite3.connect(f"file:{store.dns_db}?mode=ro", uri=True, timeout=2.0)
            cur = con.cursor()
            dns_records_count = cur.execute("SELECT COUNT(*) FROM dns_records").fetchone()[0]
            dns_tampered_count = cur.execute("SELECT COUNT(*) FROM dns_tampered").fetchone()[0]
            con.close()
        except sqlite3.Error:
            pass

    # Hosts file
    hosts_count = 0
    if store.hosts_file.is_file():
        try:
            hosts_count = sum(
                1
                for line in store.hosts_file.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip() and not line.strip().startswith("#")
            )
        except OSError:
            pass

    return {
        "active_provider": active_name,
        "available_providers": all_providers,
        "provider_dir": str(p_dir),
        "triage": triage_data,
        "pass_strategies_count": pass_strategies_count,
        "unique_domains_covered": unique_domains_count,
        "top_strategies": top_strategies,
        "dns_records_count": dns_records_count,
        "dns_tampered_count": dns_tampered_count,
        "pinned_hosts_count": hosts_count,
        "best_config_exists": store.best_config.is_file(),
    }


def subprocess_run(args: list[str], timeout: float) -> object:
    """subprocess.run helper (avoids importing subprocess at module top)."""
    import subprocess

    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


@mcp.tool()
async def probe_strategy(domain: str, strategy: str, fake_blob: str | None = None) -> ProbeResult:
    """
    Convenience alias for dbg_probe_raw: single-shot isolated strategy probe
    (dry_run_db=True default — never writes production state.db). Requires the
    `bs serve` daemon (root, netns).
    """
    return await dbg_probe_raw(domain, strategy, fake_blob, dry_run_db=True)


@mcp.resource("blockchecks://presets/manifest")
def get_presets_manifest() -> str:
    """Returns the TOML contents of presets/manifest.toml for available strategy families and domains."""
    manifest_path = get_manifest_path()
    if not manifest_path.exists():
        return "# Manifest file not found at presets/manifest.toml"
    return manifest_path.read_text(encoding="utf-8")


@mcp.resource("blockchecks://telemetry/active_run")
async def get_active_run_telemetry() -> str:
    """Returns real-time progress, total tests, PASS counts, and queue convergence for active campaigns."""
    try:
        response = await _send_daemon_request("get_telemetry", {}, timeout=5.0)
        return json.dumps(response.get("data", {}), indent=2, ensure_ascii=False)
    except Exception as err:
        return json.dumps({"error": str(err), "status": "daemon_unreachable"}, indent=2)


def main() -> None:
    """Runs the FastMCP server over standard I/O (STDIN/STDOUT)."""
    try:
        from mcp.server.fastmcp import FastMCP  # noqa: F401
    except ImportError:
        import sys

        print(  # noqa: T201, PRINT, CQ015
            "Missing optional dependency 'mcp'.\nInstall: pip install 'blockchecks[mcp]'",
            file=sys.stderr,
        )
        sys.exit(1)
    from blockchecks.engine.log import configure_logging

    configure_logging(console="stderr")
    mcp.run()


if __name__ == "__main__":
    main()
