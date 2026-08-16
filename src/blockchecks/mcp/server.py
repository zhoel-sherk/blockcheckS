"""
src/blockchecks/mcp/server.py
Model Context Protocol (MCP) Server for blockcheckS.

Exposes high-level orchestration tools, deep diagnostic/triage procedures,
and live interactive network debugging utilities over FastMCP.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from blockchecks.engine.config import PROJECT_DIR
from blockchecks.engine.paths import STATE_DIR

# ---------------------------------------------------------------------------
# FastMCP Server Initialization & Constants
# ---------------------------------------------------------------------------

mcp = FastMCP("blockcheckS Network Orchestrator & Debugger")

# Real daemon socket: STATE_DIR/blockchecks.sock (~/.local/state/blockcheckS).
# Env override preserved for tests / non-default installs.
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


# ---------------------------------------------------------------------------
# Pydantic Schemas for Tools
# ---------------------------------------------------------------------------


class TriageResult(BaseModel):
    domain: str
    l3_status: str = Field(description="L3 reachable, syn_ack, or icmp blocked")
    fail_phase: str = Field(description="Primary failure phase (e.g. TLS_RST_AT_SNI, DATA_STALL_16K, PASS)")
    client_hello_len: int = Field(description="Calculated ClientHello size in bytes")
    quic_blocked: bool = Field(description="True if QUIC Initial is dropped or rejected")
    dns_tampered: bool = Field(description="True if ISP tampered with DNS responses")
    recommended_generators: list[str] = Field(description="Strategy families recommended for this target")


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
    events: list[dict[str, Any]] = Field(description="Raw events drained from scan_bridge.lua IPC stream")
    desync_applied: bool = False
    rst_in_detected: bool = False
    rst_in_ttl: int = 0


class StrategySyntaxCheck(BaseModel):
    raw_strategy: str
    is_valid: bool
    parsed_tokens: list[str]
    escaped_conf_lines: list[str]
    detected_conflicts: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# IPC Helpers (Client for `bs serve` Unix Socket)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# LAYER A: Orchestration & Configuration Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def triage_domain(domain: str, port: int = 443) -> TriageResult:
    """
    Executes a comprehensive Preflight Triage against a target domain.
    Probes L3 connectivity, DNS integrity, TLS ClientHello sizes (Post-Quantum awareness),
    DPI RST injection phase, TCP Stream stall thresholds (7K/16K/42K), and Raw QUIC drops.
    """
    response = await _send_daemon_request("triage", {"domain": domain, "port": port}, timeout=45.0)

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
) -> str:
    """
    Generates an optimized, ready-to-use routing configuration file (nfconf)
    for Keenetic, OpenWrt, or generic Linux/systemd based on the highest-scoring PASS
    strategies in the local database.
    """
    valid_targets = {"keenetic", "openwrt", "linux"}
    if target_os.lower() not in valid_targets:
        raise ValueError(f"Invalid target_os '{target_os}'. Allowed: {', '.join(valid_targets)}")

    response = await _send_daemon_request(
        "generate_config",
        {"target_os": target_os.lower(), "domains": domains},
        timeout=15.0,
    )

    if not response.get("ok"):
        raise RuntimeError(f"Config generation failed: {response.get('error', 'Unknown error')}")

    return response.get("data", {}).get("config_content", "")


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


# ---------------------------------------------------------------------------
# LAYER B: Deep Interactive Debug Tools
# ---------------------------------------------------------------------------


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
    status = "PASS" if (r.get("status") == "PASS" or r.get("success")) else (
        "TIMEOUT" if r.get("fail_phase") == "connect_timeout" else "FAIL"
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
    rst_in_events = [e for e in events if e.get("event") == "STRATEGY_FAIL" and e.get("reason") == "rst_in"]

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

    conflicts: list[str] = []

    # Static sanity checks without requiring network daemon
    tokens = strategy_cli.strip().split()
    if not tokens:
        return StrategySyntaxCheck(
            raw_strategy=strategy_cli,
            is_valid=False,
            parsed_tokens=[],
            escaped_conf_lines=[],
            detected_conflicts=["Strategy string is empty"],
        )

    # Validate desync techniques
    has_split = any("--dpi-desync=split" in t or "split2" in t or "multisplit" in t for t in tokens)
    has_fake = any("fake" in t for t in tokens)

    if has_split and not any("--dpi-desync-split-pos" in t for t in tokens):
        conflicts.append("Split desync selected without specifying --dpi-desync-split-pos")

    if has_fake and not any("--dpi-desync-fake-tls" in t or "--dpi-desync-fake-quic" in t or "--dpi-desync-fake-http" in t for t in tokens):
        conflicts.append("Fake desync method specified without defining a fake payload source/blob")

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


# ---------------------------------------------------------------------------
# MCP Resources (Direct contextual data access for LLM)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Server Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    """Runs the FastMCP server over standard I/O (STDIN/STDOUT)."""
    try:
        from mcp.server.fastmcp import FastMCP  # noqa: F401  (re-verified at runtime)
    except ImportError:
        import sys

        print(
            "Ошибка: зависимость 'mcp' не найдена.\n"
            "Установите: pip install 'blockchecks[mcp]'",
            file=sys.stderr,
        )
        sys.exit(1)
    mcp.run()


if __name__ == "__main__":
    main()
