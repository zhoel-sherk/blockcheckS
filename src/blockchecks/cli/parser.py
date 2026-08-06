"""blockcheckS CLI — argparse and command dispatch."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Callable

from colorama import init as colorama_init

colorama_init(autoreset=True)

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
        "--adaptive",
        action="store_true",
        help="Online priority queue with cross-domain fan-out on PASS",
    )
    g.add_argument(
        "--fan-out",
        action="store_true",
        help="Shorthand: --adaptive with curl-parallel≥4 (AQ2+AQ5)",
    )
    g.add_argument(
        "--adaptive-epsilon",
        type=float,
        default=0.1,
        metavar="E",
        help="ε-greedy exploration rate (default 0.1)",
    )
    g.add_argument(
        "--no-adaptive-weights",
        action="store_true",
        help="Do not load/save scan_weights in state.db",
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


def add_lua_bridge_args(parser: argparse.ArgumentParser) -> None:
    """nfqws2 Lua bridge: /dev/shm IPC + scan_pick batch (no per-strategy restart)."""
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
    add_system_deps_args(udp)

    scan = sub.add_parser("scan", help="Async TCP strategy batch scan")
    scan.add_argument("-d", "--domain", default=None)
    scan.add_argument(
        "--generate",
        nargs="?",
        const="custom,configs",
        default="",
        help="Use matrix generator (sources: custom,configs,fake,faked,...)",
    )
    scan.add_argument(
        "--preset", default=None, help="Domain preset name (presets/domains/{name}.txt)"
    )
    scan.add_argument(
        "-M", "--strategy-preset", default=None, help="Strategy preset (presets/strategies/{name})"
    )
    scan.add_argument(
        "--disable-ech",
        action="store_true",
        help="Disable Encrypted Client Hello (force plaintext SNI)",
    )
    scan.add_argument(
        "--no-wssize",
        action="store_true",
        default=False,
        help="Skip wssize fallback on TLS 1.2 FAIL (faster, lower coverage)",
    )
    scan.add_argument("--list-presets", action="store_true", help="List available presets and exit")
    scan.add_argument(
        "--protocol",
        default="tls12",
        choices=["tls12", "tls13"],
        help="TLS protocol version to test",
    )
    scan.add_argument("--scan-level", default="fast", choices=["single", "fast", "full"])
    scan.add_argument("--parallel", type=int, default=effective_default_pool_size())
    scan.add_argument("--max", type=int, default=100)
    scan.add_argument("--timeout", type=float, default=3.0)
    scan.add_argument("--user-matrix", default="")
    add_store_args(scan)
    scan.add_argument(
        "--db-batch",
        type=int,
        default=500,
        help="Buffer N DB writes before flush (0=immediate, default)",
    )
    scan.add_argument("--resume", action="store_true")
    add_secure_dns_args(scan, include_preflight=True)
    add_system_deps_args(scan)
    add_curl_repeats_args(scan)
    add_family_gate_args(scan)
    add_domain_filter_args(scan)
    add_adaptive_args(scan)
    add_curl_fanout_args(scan)
    add_lua_bridge_args(scan)
    add_time_limit_args(scan, include_export=True)
    scan.add_argument("--export-limit", type=int, default=3)
    scan.add_argument(
        "--no-common-only",
        action="store_true",
        help="Export best per-domain instead of COMMON intersection",
    )
    scan.add_argument("--tcp-sources", default="")
    scan.add_argument(
        "--nfqws2-debug",
        nargs="?",
        const="1",
        default=None,
        help="nfqws2 --debug: 1=logs/file, syslog, or @path/path",
    )

    composite = sub.add_parser("composite", help="Test composite nfqws2 config")
    composite.add_argument("-c", "--config", required=True, help="Path to composite .conf file")
    composite.add_argument(
        "-d", "--domains", nargs="+", help="Domains to test (default: Discord set)"
    )
    composite.add_argument("--parallel", type=int, default=effective_default_pool_size())
    composite.add_argument("--timeout", type=float, default=3.0)
    add_system_deps_args(composite)

    pair = sub.add_parser("pair", help="TCP x UDP pair matrix (async)")
    pair.add_argument("-d", "--domain", default=None)
    pair.add_argument(
        "--generate", nargs="?", const="custom,configs", default="", help="Use matrix generator"
    )
    pair.add_argument(
        "--tcp-sources",
        default="custom,configs",
        help="TCP sources: custom,configs,fake,faked (fakedsplit),hostfake,fake_multi,fake_faked (fake+fakedsplit)",
    )
    pair.add_argument("--udp-sources", default="custom", help="UDP sources: custom,configs")
    pair.add_argument(
        "--preset", default=None, help="Domain preset name (presets/domains/{name}.txt)"
    )
    pair.add_argument(
        "--disable-ech",
        action="store_true",
        help="Disable Encrypted Client Hello (force plaintext SNI)",
    )
    pair.add_argument(
        "--no-wssize",
        action="store_true",
        default=False,
        help="Skip wssize fallback on TLS 1.2 FAIL (faster, lower coverage)",
    )
    pair.add_argument("--list-presets", action="store_true", help="List available presets and exit")
    pair.add_argument(
        "-M", "--strategy-preset", default=None, help="Strategy preset (presets/strategies/{name})"
    )
    pair.add_argument(
        "--protocol",
        default="tls12",
        choices=["tls12", "tls13"],
        help="TLS protocol version to test",
    )
    pair.add_argument("--scan-level", default="fast", choices=["single", "fast", "full"])
    pair.add_argument("--parallel", type=int, default=effective_default_pool_size())
    pair.add_argument("--max", type=int, default=100)
    pair.add_argument("--timeout", type=float, default=3.0)
    pair.add_argument("--udp-timeout", type=float, default=3.0)
    pair.add_argument(
        "--tcp-only", action="store_true", help="Skip UDP pair testing (TCP scan only)"
    )
    pair.add_argument("-c", "--config", help="Single TCP .conf file")
    pair.add_argument("-u", "--udp-config", help="Single UDP .conf file")
    pair.add_argument("-C", "--configs-dir", default=CONFIGS_DIR)
    pair.add_argument("--ip", default=DEFAULT_VOICE_IP)
    pair.add_argument("--port", type=int, default=DEFAULT_VOICE_PORT)
    pair.add_argument(
        "--discover-dns",
        nargs="?",
        const=5,
        type=int,
        default=None,
        help="DNS + Maks-gaming IP list + dual UDP probe (no VPN)",
    )
    pair.add_argument(
        "--discover-dns-no-bootstrap",
        action="store_true",
        help="Skip nfqws2 UDP bootstrap during --discover-dns",
    )
    pair.add_argument(
        "--auto-discover",
        nargs="?",
        const=5,
        type=int,
        default=None,
        help="DNS + gateway discover via sing-box (VPN path)",
    )
    pair.add_argument("--full-voice", action="store_true")
    pair.add_argument("--udp-bypass", action="store_true")
    pair.add_argument("--user-matrix", default="", help="Path to custom strategy list file")
    add_store_args(pair)
    pair.add_argument(
        "--db-batch",
        type=int,
        default=500,
        help="Buffer N DB writes before flush (0=immediate, default)",
    )
    pair.add_argument("--resume", action="store_true")
    add_secure_dns_args(pair, include_preflight=True)
    add_system_deps_args(pair)
    add_curl_repeats_args(pair)
    add_family_gate_args(pair)
    add_domain_filter_args(pair)
    add_adaptive_args(pair)
    add_curl_fanout_args(pair)
    add_lua_bridge_args(pair)
    add_time_limit_args(pair, include_export=True)
    pair.add_argument("--export-limit", type=int, default=3)
    pair.add_argument(
        "--no-common-only",
        action="store_true",
        help="Export best per-domain instead of COMMON intersection",
    )
    pair.add_argument(
        "--nfqws2-debug",
        nargs="?",
        const="1",
        default=None,
        help="nfqws2 --debug: 1=logs/file, syslog, or @path/path",
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
                or getattr(a, "udp_sources", "") != "custom"
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
    from blockchecks.engine.paths import apply_pycache_prefix, ensure_dirs

    apply_pycache_prefix()
    ensure_dirs()
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

    finalize_store_args(args, user_cfg)
    from blockchecks.engine.run_deadline import validate_time_limit_args

    validate_time_limit_args(parser, args)
    return dispatch(args)
