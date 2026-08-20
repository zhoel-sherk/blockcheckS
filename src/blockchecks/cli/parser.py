"""blockcheckS CLI — argparse and command dispatch."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Callable

from blockchecks.terminal import init_terminal

init_terminal()

from blockchecks.cli.commands.pair import cmd_pair
from blockchecks.cli.commands.tcp import cmd_tcp
from blockchecks.cli.commands.udp import cmd_udp
from blockchecks.cli.presets import list_presets
from blockchecks.engine.config import (
    CONFIGS_DIR,
    DEFAULT_BRIDGE_BATCH,
    DEFAULT_VOICE_IP,
    DEFAULT_VOICE_PORT,
    effective_default_pool_size,
)
from blockchecks.engine.paths import DEFAULT_DB_PATH, DEFAULT_OUT_DIR
from blockchecks.engine.settle_profile import DEFAULT_PROFILE_PATH


def add_store_args(parser: argparse.ArgumentParser, *, include_out_dir: bool = True) -> None:
    """Shared --db / --out-dir (XDG defaults applied post-parse)."""
    parser.add_argument(
        "--db",
        default=None,
        help=f"State DB (default: {DEFAULT_DB_PATH})",
    )
    if include_out_dir:
        parser.add_argument(
            "--out-dir",
            default=None,
            help=f"Export nfconf on finish (default for full: {DEFAULT_OUT_DIR})",
        )


def add_adaptive_args(parser: argparse.ArgumentParser) -> None:
    """AQ flags (full + scan/pair)."""
    g = parser.add_argument_group("adaptive queue (AQ)")
    g.add_argument(
        "--no-adaptive",
        action="store_true",
        help="Disable adaptive priority queue (run purely sequential matrix; default: adaptive ON)",
    )
    g.add_argument(
        "--adaptive",
        action="store_false",
        dest="no_adaptive",
        help="Enable adaptive priority queue (default: ON)",
    )
    g.add_argument(
        "--fan-out",
        action="store_true",
        help="Shorthand: adaptive with curl-parallel>=4 (AQ2+AQ5)",
    )
    g.add_argument(
        "--adaptive-epsilon",
        type=float,
        default=0.1,
        metavar="E",
        help="epsilon-greedy exploration rate (default 0.1)",
    )
    g.add_argument(
        "--no-adaptive-weights",
        action="store_true",
        help="Do not load/save scan_weights in state.db",
    )


def add_profile_args(parser: argparse.ArgumentParser) -> None:
    """Register --profile smoke|fast|20h."""
    parser.add_argument(
        "--profile",
        choices=["smoke", "fast", "20h"],
        default=None,
        help="Predefined flag bundle (smoke=quick 20-item, fast=100-item, 20h=long-term series)",
    )


def add_time_limit_args(parser: argparse.ArgumentParser, *, include_export: bool = False) -> None:
    """Register --max-timeh / --max-timem."""
    from blockchecks.engine.run_deadline import add_time_limit_args as _add

    _add(parser, include_export=include_export)


def add_curl_fanout_args(parser: argparse.ArgumentParser) -> None:
    from blockchecks.engine.config import DEFAULT_CURL_PARALLEL, MAX_CURL_PARALLEL

    g = parser.add_argument_group("curl fan-out (B2)")
    g.add_argument(
        "--curl-parallel",
        type=int,
        default=DEFAULT_CURL_PARALLEL,
        metavar="N",
        help=f"Domains per nfqws2 session (1=off, max {MAX_CURL_PARALLEL})",
    )


def add_curl_repeats_args(
    parser: argparse.ArgumentParser, *, include_quic_timeout: bool = False
) -> None:
    """BC2-4: blockcheck2-style curl repeats per strategy."""
    g = parser.add_argument_group("curl repeats")
    g.add_argument(
        "--repeats",
        type=int,
        default=1,
        metavar="N",
        help="curl attempts per strategy (blockcheck2 REPEATS, 1-10, default 1)",
    )
    g.add_argument(
        "--parallel-repeats",
        action="store_true",
        help="Run repeats in parallel (blockcheck2 PARALLEL / GP repeat_parallel)",
    )
    g.add_argument(
        "--repeats-mode",
        choices=["fast", "stable"],
        default="fast",
        help="fast=stop on first PASS; stable=run all N like blockcheck2 (PASS if any)",
    )
    if include_quic_timeout:
        g.add_argument(
            "--quic-timeout",
            type=float,
            default=8.0,
            help="HTTP/3 curl timeout (BC2-10, default 8s)",
        )


def add_backend_args(parser: argparse.ArgumentParser) -> None:
    """Probe-backend selection shared by all commands.

    Precedence: ``--classic`` > ``--probe-backend`` > ``--lua-bridge`` >
    ``BLOCKCHECKS_PROBE_BACKEND`` (default lua_bridge). ``--classic`` /
    ``--probe-backend`` are meaningful everywhere (incl. single tcp/udp);
    lua-specific flags are added only by ``add_lua_bridge_args``.
    """
    g = parser.add_argument_group("probe backend")
    g.add_argument(
        "--classic",
        action="store_true",
        help="Force legacy classic backend (per-strategy nfqws2 restart); "
        "overrides --probe-backend / --lua-bridge / BLOCKCHECKS_PROBE_BACKEND",
    )
    g.add_argument(
        "--probe-backend",
        choices=("classic", "lua_bridge"),
        default=None,
        metavar="{classic,lua_bridge}",
        help="Explicit probe backend (default lua_bridge unless overridden)",
    )


def add_lua_bridge_args(parser: argparse.ArgumentParser) -> None:
    """nfqws2 Lua bridge: /dev/shm IPC + scan_pick batch (no per-strategy restart).

    Backend selection (T-L3/T-L4/T-L5): default is ``lua_bridge``. Precedence:
    ``--classic`` > ``--probe-backend`` > ``--lua-bridge`` > ``BLOCKCHECKS_PROBE_BACKEND``.
    """
    add_backend_args(parser)
    g = parser.add_argument_group("lua bridge (scan_pick IPC)")
    g.add_argument(
        "--lua-bridge",
        action="store_true",
        help="Hot-swap strategies via WRITABLE/shm (persistent nfqws2 per batch)",
    )
    g.add_argument(
        "--bridge-batch",
        type=int,
        default=DEFAULT_BRIDGE_BATCH,
        metavar="N",
        help=f"Strategies per bridge conf window (default {DEFAULT_BRIDGE_BATCH})",
    )
    g.add_argument(
        "--lua-bridge-compare",
        action="store_true",
        help="Run classic + bridge paths and log verdict drift",
    )
    g.add_argument(
        "--lua-extra",
        nargs="*",
        default=[],
        metavar="PATH",
        help="Extra --lua-init=@ paths after zapret-auto (custom Lua hooks)",
    )


def add_domain_filter_args(parser: argparse.ArgumentParser) -> None:
    """Phase 11 A1: denylist filter for domain presets."""
    g = parser.add_argument_group("domain filter")
    g.add_argument(
        "--allow-unsafe-domains",
        action="store_true",
        help="Do not apply presets/domains/denylist.txt to --preset loads",
    )


def add_protocol_phase_args(parser: argparse.ArgumentParser) -> None:
    """Phase 11 A10 — GP ENABLE_* mirror flags for bs full."""
    g = parser.add_argument_group("protocol phases (GP mirror)")
    g.add_argument("--http-off", action="store_true", help="Skip HTTP :80 phase (= --no-http)")
    g.add_argument("--http3-off", action="store_true", help="Skip QUIC HTTP/3 phase (= --no-quic)")
    g.add_argument(
        "--tls12-off",
        action="store_true",
        help="Skip TCP TLS phase when --protocol tls12",
    )
    g.add_argument(
        "--tls13-off",
        action="store_true",
        help="Skip TCP TLS phase when --protocol tls13",
    )


def add_family_gate_args(parser: argparse.ArgumentParser) -> None:
    """BC2-6: blockcheck2 need_* family gating."""
    g = parser.add_argument_group("family gates")
    g.add_argument(
        "--no-family-gates",
        action="store_true",
        help="Disable need_* gating between standard families (default: on for single/fast)",
    )


def add_ip_pin_args(parser: argparse.ArgumentParser) -> None:
    """IP pinning (IP-PIN) flags — scan/pair only (runner-level auto-pin)."""
    g = parser.add_argument_group("IP pinning")
    g.add_argument(
        "--fixed-ip",
        default=None,
        help=(
            "Hosts-analog IP pin file (one 'domain IP' per line, # comments). "
            "Pinned IPs override DoH order; auto-refreshed at startup. "
            "Default: $BLOCKCHECKS_FIXED_IP"
        ),
    )
    g.add_argument(
        "--no-auto-pin",
        action="store_true",
        help="Disable auto-probing of pinned/DoH IPs at startup (use pins as-is)",
    )


def add_secure_dns_args(
    parser: argparse.ArgumentParser, *, include_preflight: bool = False
) -> None:
    """CLI flags for Phase 9 secure DNS (SD5); optional preflight group."""
    g = parser.add_argument_group("secure DNS")
    g.add_argument(
        "--no-secure-dns",
        action="store_true",
        help="Disable DoH pre-resolve (default: on)",
    )
    g.add_argument("--doh-server", default=None, help="Fixed DoH server URL")
    g.add_argument("--skip-dns-audit", action="store_true", help="Skip UDP vs DoH audit table")
    g.add_argument(
        "--allow-dns-hijack",
        action="store_true",
        help="Continue when DNS hijack detected",
    )
    g.add_argument(
        "--data-block-sync",
        action="store_true",
        help="Commit+push data_block/ (provider DNS cache, strategies) after scan",
    )
    if not include_preflight:
        return
    g = parser.add_argument_group("preflight")
    g.add_argument(
        "--no-preflight",
        action="store_true",
        help="Skip all preflight checks (prolog, IP-block, port-block, baseline)",
    )
    g.add_argument(
        "--quick",
        action="store_true",
        help="Quick preflight: run prolog only, skip deep baseline/IP-block/port-block probes",
    )
    g.add_argument("--skip-ip-block", action="store_true", help="Skip IP-block cross-test")
    g.add_argument(
        "--unblocked-dom",
        default=None,
        help="Reference unblocked domain (default: ripe.net)",
    )
    g.add_argument("--skip-baseline", action="store_true", help="Skip unblocked baseline check")
    g.add_argument("--skip-port-block", action="store_true", help="Skip TCP port probes")
    g.add_argument("--skip-prolog", action="store_true", help="Skip no-bypass prolog curl")
    g.add_argument(
        "--prolog-content",
        action="store_true",
        help="Validate HTTP body content during prolog (stricter than TLS-only)",
    )
    g.add_argument(
        "--force",
        action="store_true",
        help="Run strategy tests even if prolog passes",
    )
    g.add_argument("--skip-nfqws2-check", action="store_true", help="Skip host nfqws2 detection")
    g.add_argument(
        "--abort-on-nfqws2",
        action="store_true",
        help="Abort if nfqws2 already running on host",
    )


def add_system_deps_args(parser: argparse.ArgumentParser) -> None:
    """Host tool / zapret2 vendor fetch flags (1.0.1)."""
    g = parser.add_argument_group("system dependencies")
    g.add_argument(
        "--no-fetch-deps",
        action="store_true",
        help="Do not auto-download zapret2/nfqws2 when missing (BLOCKCHECKS_FETCH_DEPS=0)",
    )
    g.add_argument(
        "--offline",
        action="store_true",
        help="Never contact the network for dependency fetch",
    )
    g.add_argument(
        "--skip-deps-check",
        action="store_true",
        help="Skip verify_system_dependencies (advanced)",
    )


def add_campaign_args(parser: argparse.ArgumentParser, *, mode: str = "full") -> None:
    """Unified argument builder for scan, pair, and full matrix campaigns.

    Synchronizes flag names and default values across all campaign commands.
    """
    if mode in ("scan", "pair"):
        parser.add_argument("-d", "--domain", default=None, help="Target domain (e.g. youtube.com)")
    else:  # full
        parser.add_argument("-d", "--domain", help="Single domain to test")
        parser.add_argument("--domains-file", help="Path to domain list file")

    parser.add_argument(
        "--preset", default=None, help="Domain preset name (presets/domains/{name}.txt)"
    )
    parser.add_argument(
        "-M", "--strategy-preset", default=None, help="Strategy preset (presets/strategies/{name})"
    )
    parser.add_argument(
        "--generate",
        nargs="?",
        const="custom,configs",
        default="",
        help="Use matrix generator (sources: custom,configs,fake,faked,...)",
    )
    parser.add_argument(
        "--tcp-sources",
        default="standard,custom,configs,flowseal"
        if mode == "full"
        else ("custom,configs" if mode == "pair" else ""),
        help="TCP strategy sources (comma-separated)",
    )

    if mode in ("pair", "full"):
        parser.add_argument(
            "--udp-sources",
            default="custom,standard_udp",
            help="UDP sources: custom,standard_udp,configs,flowseal,game",
        )

    if mode == "full":
        parser.add_argument("--quic-sources", default="standard_quic")
        parser.add_argument("--http-sources", default="custom,standard_http")
        parser.add_argument("--no-http", action="store_true", help="Skip HTTP :80 strategy phase")
        parser.add_argument("--no-quic", action="store_true", help="Skip QUIC strategy phase")
        parser.add_argument("--no-voice", action="store_true", help="Skip UDP voice phase")
        parser.add_argument(
            "--tcp-only", action="store_true", help="Skip UDP, QUIC, and HTTP phases"
        )

    parser.add_argument(
        "--no-ech",
        "--disable-ech",
        dest="disable_ech",
        action="store_true",
        help="Disable Encrypted Client Hello (force plaintext SNI)",
    )
    parser.add_argument(
        "--no-wssize",
        action="store_true",
        default=False,
        help="Skip wssize fallback on TLS 1.2 FAIL (faster, lower coverage)",
    )
    if mode in ("scan", "pair"):
        parser.add_argument(
            "--list-presets", action="store_true", help="List available presets and exit"
        )

    parser.add_argument(
        "--protocol",
        default="tls12",
        choices=["tls12", "tls13"],
        help="TLS protocol version to test",
    )
    parser.add_argument(
        "--scan-level",
        default="full" if mode == "full" else "fast",
        choices=["single", "fast", "full"],
        help="Scan thoroughness level",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=effective_default_pool_size(),
        help="Parallel netns pool size",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=0 if mode == "full" else 100,
        help="Cap strategy matrix count (0=uncapped)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Curl probe timeout in seconds (default: 3.0)",
    )
    if mode in ("pair", "full"):
        parser.add_argument(
            "--udp-timeout",
            type=float,
            default=3.0,
            help="UDP voice probe timeout in seconds (default: 3.0)",
        )
    parser.add_argument("--user-matrix", default="", help="Path to custom strategy list file")

    add_store_args(parser)
    parser.add_argument(
        "--db-batch",
        type=int,
        default=500,
        help="Buffer N DB writes before flush (default 500)",
    )
    parser.add_argument(
        "--resume", action="store_true", help="Resume prior run: skip domain×strategy in DB"
    )

    add_secure_dns_args(parser, include_preflight=True)
    add_ip_pin_args(parser)
    add_system_deps_args(parser)
    add_curl_repeats_args(parser, include_quic_timeout=(mode == "full"))
    add_family_gate_args(parser)
    add_domain_filter_args(parser)
    add_adaptive_args(parser)
    add_curl_fanout_args(parser)
    add_profile_args(parser)
    add_lua_bridge_args(parser)
    add_time_limit_args(parser, include_export=True)

    parser.add_argument(
        "--export-limit", type=int, default=3, help="Max strategies to export per category"
    )
    parser.add_argument(
        "--no-common-only",
        action="store_true",
        help="Export best per-domain instead of COMMON intersection",
    )

    if mode in ("pair", "full"):
        parser.add_argument("--ip", default=DEFAULT_VOICE_IP, help="Discord voice server IP")
        parser.add_argument(
            "--port", type=int, default=DEFAULT_VOICE_PORT, help="Discord voice server UDP port"
        )
        parser.add_argument(
            "--discover-dns",
            nargs="?",
            const=5,
            type=int,
            default=5 if mode == "full" else None,
            help="DNS + Maks-gaming IP list + dual UDP probe (no VPN)",
        )
        parser.add_argument(
            "--discover-dns-no-bootstrap",
            action="store_true",
            help="Skip nfqws2 UDP bootstrap during --discover-dns",
        )
        parser.add_argument(
            "--auto-discover",
            nargs="?",
            const=5,
            type=int,
            default=None,
            help="DNS + gateway discover via sing-box (VPN path)",
        )
        parser.add_argument(
            "--voice-region",
            default=os.environ.get("BLOCKCHECKS_VOICE_REGION", "finland"),
            metavar="REGION",
            help="Discord voice region for endpoint discovery",
        )
        parser.add_argument(
            "--voice-burst",
            action="store_true",
            help="Also probe with a >16KB UDP media burst (voice-traffic heuristic)",
        )
        parser.add_argument(
            "--full-voice", action="store_true", help="Complete Discord voice gateway handshake"
        )
        parser.add_argument(
            "--udp-bypass", action="store_true", help="Probe UDP through bypass path"
        )

    if mode == "pair":
        parser.add_argument(
            "--tcp-only", action="store_true", help="Skip UDP pair testing (TCP scan only)"
        )
        parser.add_argument("-c", "--config", help="Single TCP .conf file")
        parser.add_argument("-u", "--udp-config", help="Single UDP .conf file")
        parser.add_argument(
            "-C", "--configs-dir", default=CONFIGS_DIR, help="Directory of TCP configs"
        )

    if mode == "full":
        parser.add_argument(
            "--pair-max", type=int, default=200, help="Cap TCP×UDP pair combinations"
        )
        parser.add_argument(
            "--isp-interface", default="eth3", help="Router WAN interface for exported conf"
        )
        parser.add_argument("--prefix", default="/opt/etc/nfqws2", help="Router nfqws2 prefix path")
        parser.add_argument("--mode", default="auto", choices=["auto", "list", "all"])
        add_protocol_phase_args(parser)
        g = parser.add_argument_group("settle profile (B11)")
        g.add_argument(
            "--settle-profile",
            default=None,
            metavar="PATH",
            help="Load settle/curl timings from bench-settle JSON",
        )
        g.add_argument(
            "--no-settle-profile",
            action="store_true",
            help="Ignore settle profile even if logs/settle_profile.json exists",
        )

    parser.add_argument(
        "--nfqws2-debug",
        nargs="?",
        const="1",
        default=None,
        help="nfqws2 --debug: 1=logs/file, syslog, or @path/path",
    )


def ensure_system_deps_or_exit(args) -> int:
    """Run deps check before live nfqws2 work. Returns 0 or error exit code."""
    if getattr(args, "skip_deps_check", False):
        return 0
    from blockchecks.engine.system_deps import verify_system_dependencies

    fetch = not getattr(args, "no_fetch_deps", False)
    offline = bool(getattr(args, "offline", False))
    report = verify_system_dependencies(fetch=fetch, offline=offline)
    report.print_report()
    if not report.ok:
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="blockcheckS - lightspeed DPI strategy tester")
    sub = parser.add_subparsers(dest="command", help="Commands")

    sub.add_parser(
        "full",
        help="Mass strategy×coverage test + nfqws2 conf export (see: bs full -h)",
    )

    stop = sub.add_parser(
        "stop",
        help="Gracefully stop active full/scan/pair run (SIGTERM → flush → export)",
    )
    stop.add_argument(
        "--force",
        action="store_true",
        help="SIGKILL if graceful shutdown exceeds --wait",
    )
    stop.add_argument(
        "--wait",
        type=float,
        default=120.0,
        metavar="SEC",
        help="Seconds to wait for graceful shutdown (default 120)",
    )

    serve = sub.add_parser(
        "serve",
        help="Run resident probe server (Unix socket + HTTP bridge, on-the-fly)",
    )
    serve.add_argument(
        "--pool",
        type=int,
        default=None,
        help="Netns pool size (default: effective default)",
    )
    serve.add_argument(
        "--bridge-batch",
        type=int,
        default=500,
        help="Lua bridge batch size (default 500)",
    )
    serve.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Default probe timeout seconds (default 3)",
    )
    serve.add_argument(
        "--classic",
        action="store_true",
        help="Use classic backend instead of lua_bridge",
    )
    serve.add_argument(
        "--http-port",
        type=int,
        default=None,
        help="Also expose an authenticated HTTP bridge on 127.0.0.1:PORT (optional)",
    )
    serve.add_argument(
        "--http-token",
        type=str,
        default=None,
        help="Bearer token for the HTTP bridge (default: BLOCKCHECKS_HTTP_TOKEN env "
        "or config.toml [http] token)",
    )

    tcp = sub.add_parser("tcp", help="Single TCP strategy test (sync)")
    tcp.add_argument("-d", "--domain", required=True)
    tcp.add_argument("-s", "--strategy")
    tcp.add_argument("-c", "--config")
    tcp.add_argument("-C", "--configs-dir")
    tcp.add_argument("-f", "--file")
    tcp.add_argument("--test", choices=["custom", "standard"])
    tcp.add_argument("--test-dir", default="/opt/zapret2/blockcheck2.d")
    tcp.add_argument(
        "--protocol", default="tls12", choices=["http", "tls12", "tls13", "quic", "udp_voice"]
    )
    tcp.add_argument("--timeout", type=float, default=3.0)
    tcp.add_argument("--no-hostlist", action="store_true")
    tcp.add_argument("--qnum", type=int, default=200)
    tcp.add_argument("--ns")
    add_secure_dns_args(tcp)
    add_system_deps_args(tcp)
    add_time_limit_args(tcp)
    add_curl_repeats_args(tcp)
    add_backend_args(tcp)
    tcp.add_argument(
        "--nfqws2-debug",
        nargs="?",
        const="1",
        default=None,
        help="nfqws2 --debug: 1=logs/file, syslog, or @path/path",
    )

    udp = sub.add_parser("udp", help="Single UDP strategy test (sync)")
    udp.add_argument("-c", "--config")
    udp.add_argument("-C", "--configs-dir")
    udp.add_argument("--ip", default=DEFAULT_VOICE_IP)
    udp.add_argument("--port", type=int, default=DEFAULT_VOICE_PORT)
    udp.add_argument(
        "--discover-dns",
        nargs="?",
        const=5,
        type=int,
        default=None,
        help="DNS + Maks-gaming IP list + dual UDP probe (no VPN)",
    )
    udp.add_argument(
        "--discover-dns-no-bootstrap",
        action="store_true",
        help="Skip nfqws2 UDP bootstrap during --discover-dns",
    )
    udp.add_argument(
        "--auto-discover",
        nargs="?",
        const=5,
        type=int,
        default=None,
        help="DNS + gateway discover via sing-box (VPN path)",
    )
    udp.add_argument(
        "--voice-region",
        default=os.environ.get("BLOCKCHECKS_VOICE_REGION", "finland"),
        metavar="REGION",
        help="Discord voice region for endpoint discovery "
        "(finland/russia/frankfurt/…; default BLOCKCHECKS_VOICE_REGION or finland)",
    )
    udp.add_argument(
        "--voice-burst",
        action="store_true",
        help="Also probe with a >16KB UDP media burst (voice-traffic heuristic; "
        "detects endpoints that only answer a sustained stream)",
    )
    udp.add_argument("--timeout", type=float, default=3.0)
    udp.add_argument("--qnum", type=int, default=201)
    udp.add_argument("--ns")
    udp.add_argument(
        "--nfqws2-debug",
        nargs="?",
        const="1",
        default=None,
        help="nfqws2 --debug: 1=logs/file, syslog, or @path/path",
    )
    add_backend_args(udp)
    add_system_deps_args(udp)

    scan = sub.add_parser("scan", help="Async TCP strategy batch scan")
    add_campaign_args(scan, mode="scan")

    composite = sub.add_parser("composite", help="Test composite nfqws2 config")
    composite.add_argument("-c", "--config", required=True, help="Path to composite .conf file")
    composite.add_argument(
        "-d", "--domains", nargs="+", help="Domains to test (default: Discord set)"
    )
    composite.add_argument("--parallel", type=int, default=effective_default_pool_size())
    composite.add_argument("--timeout", type=float, default=3.0)
    add_system_deps_args(composite)

    pair = sub.add_parser("pair", help="TCP x UDP pair matrix (async)")
    add_campaign_args(pair, mode="pair")

    sub.add_parser(
        "mcp",
        help="Model Context Protocol server (stdio) bridging LLM → bs serve daemon",
    )

    bench = sub.add_parser("bench-settle", help="Benchmark nfqws2 settle × curl timeout (A9)")
    bench.add_argument("-d", "--domain", default="discord.com")
    bench.add_argument("-s", "--strategy", default=None, help="Single inline strategy")
    bench.add_argument(
        "-M",
        "--strategy-preset",
        default="timeout-benchmark",
        help="Strategy preset (default: timeout-benchmark)",
    )
    bench.add_argument(
        "--settle-times",
        default="",
        help="Comma-separated settle max seconds (default: 0.1,0.2,0.5,1,2)",
    )
    bench.add_argument(
        "--curl-timeouts",
        default="",
        help="Comma-separated curl timeouts (default: 0.5,1,1.5,2)",
    )
    bench.add_argument("--max-strategies", type=int, default=3)
    bench.add_argument("--no-secure-dns", action="store_true")
    bench.add_argument(
        "--write-profile",
        nargs="?",
        const=DEFAULT_PROFILE_PATH,
        default=None,
        metavar="PATH",
        help=f"Write settle profile JSON (default: {DEFAULT_PROFILE_PATH})",
    )
    bench.add_argument(
        "--no-write-profile",
        action="store_true",
        help="Skip writing settle profile JSON",
    )
    add_system_deps_args(bench)

    return parser


def dispatch(args: argparse.Namespace) -> int:
    dbg = getattr(args, "nfqws2_debug", None)
    if dbg is not None:
        os.environ["BLOCKCHECKS_NFQWS2_DEBUG"] = str(dbg)

    live = {"tcp", "udp", "scan", "pair", "composite", "bench-settle"}
    # Skip deps when listing presets under scan/pair.
    if args.command in live and not (
        args.command in {"scan", "pair"} and getattr(args, "list_presets", False)
    ):
        code = ensure_system_deps_or_exit(args)
        if code:
            return code

    def _scan(a: argparse.Namespace) -> int:
        if getattr(a, "list_presets", False):
            list_presets()
            return 0
        if a.generate:
            a.tcp_sources = (
                a.generate if a.generate != "custom,configs" else a.tcp_sources or "custom,configs"
            )
        a.generate = bool(a.generate)
        a.tcp_only = True
        a.udp_sources = ""
        a.configs_dir = CONFIGS_DIR
        a.config = None
        a.udp_config = None
        # Pair-only attrs not on scan CLI — set safe defaults for cmd_pair.
        a.full_voice = False
        a.udp_bypass = False
        a.auto_discover = None
        a.ip = DEFAULT_VOICE_IP
        a.port = DEFAULT_VOICE_PORT
        a.udp_timeout = 3.0
        return asyncio.run(cmd_pair(a))

    def _pair(a: argparse.Namespace) -> int:
        if getattr(a, "list_presets", False):
            list_presets()
            return 0
        if a.generate and a.generate != "custom,configs":
            a.tcp_sources = a.generate
        if getattr(a, "config", None) or getattr(a, "udp_config", None):
            a.generate = False
        else:
            a.generate = bool(a.generate) or bool(
                getattr(a, "tcp_sources", "") != "custom,configs"
                or getattr(a, "udp_sources", "") != "custom,standard_udp"
            )
        return asyncio.run(cmd_pair(a))

    def _composite(a: argparse.Namespace) -> int:
        from blockchecks.checkers.composite_runner import run as run_composite

        return asyncio.run(run_composite(a.config, a.domains, a.parallel, a.timeout))

    def _bench(a: argparse.Namespace) -> int:
        from blockchecks.cli.commands.bench_settle import cmd_bench_settle

        return asyncio.run(cmd_bench_settle(a))

    def _stop(a: argparse.Namespace) -> int:
        from blockchecks.cli.commands.stop import cmd_stop

        return cmd_stop(a)

    handlers: dict[str, Callable[[argparse.Namespace], int]] = {
        "tcp": cmd_tcp,
        "udp": cmd_udp,
        "scan": _scan,
        "pair": _pair,
        "composite": _composite,
        "bench-settle": _bench,
        "stop": _stop,
    }
    handler = handlers.get(args.command)
    if handler is not None:
        return handler(args)

    build_parser().print_help()
    return 1


def main(argv: list[str] | None = None) -> int:
    """Entry point — pydantic CliApp (flag defs still from build_parser helpers)."""
    import os

    # Escape hatch for bisect / legacy automation
    if os.environ.get("BLOCKCHECKS_ARGPARSE", "").strip() in ("1", "true", "yes"):
        return _main_argparse(argv)

    from blockchecks.cli.cliapp import main as cliapp_main

    return cliapp_main(argv)


def _main_argparse(argv: list[str] | None = None) -> int:
    from blockchecks.cli.user_config import (
        apply_parser_defaults,
        finalize_store_args,
        load_user_config,
    )
    from blockchecks.engine.paths import apply_pycache_prefix, configure_logging, ensure_dirs

    apply_pycache_prefix()
    ensure_dirs()
    configure_logging()
    user_cfg = load_user_config()
    paths_cfg = user_cfg.get("paths") if isinstance(user_cfg.get("paths"), dict) else {}
    migrate_on = True if paths_cfg.get("migrate") is None else bool(paths_cfg.get("migrate"))
    from blockchecks.engine.paths import migrate_legacy_state_db

    migrate_legacy_state_db(enabled=migrate_on)

    if argv is None:
        argv = sys.argv[1:]
    if len(argv) > 0 and argv[0] == "full":
        from blockchecks.main import main as full_main

        return full_main(argv[1:], user_config=user_cfg)

    parser = build_parser()
    apply_parser_defaults(parser, user_cfg)
    old_argv = sys.argv
    try:
        sys.argv = ["bs", *argv]
        args = parser.parse_args(argv)
    finally:
        sys.argv = old_argv

    from blockchecks.cli.profiles import flags_present_in_argv

    args._explicit_cli = flags_present_in_argv(argv)
    finalize_store_args(args, user_cfg)
    from blockchecks.engine.run_deadline import validate_time_limit_args

    validate_time_limit_args(parser, args)
    return dispatch(args)
