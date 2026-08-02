"""blockcheckS CLI — argparse and command dispatch."""

import argparse
import asyncio
import os
import sys

from colorama import init as colorama_init

colorama_init(autoreset=True)

from blockchecks.cli.commands.pair import cmd_pair
from blockchecks.cli.commands.tcp import cmd_tcp
from blockchecks.cli.commands.udp import cmd_udp
from blockchecks.cli.presets import list_presets
from blockchecks.engine.config import CONFIGS_DIR, DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
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


def add_curl_repeats_args(parser: argparse.ArgumentParser) -> None:
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
    g.add_argument(
        "--quic-timeout",
        type=float,
        default=8.0,
        help="HTTP/3 curl timeout (BC2-10, default 8s)",
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


def add_secure_dns_args(parser: argparse.ArgumentParser) -> None:
    """CLI flags for Phase 9 secure DNS (SD5)."""
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
    g = parser.add_argument_group("preflight")
    g.add_argument("--skip-ip-block", action="store_true", help="Skip IP-block cross-test")
    g.add_argument(
        "--unblocked-dom",
        default=None,
        help="Reference unblocked domain (default: iana.org)",
    )
    g.add_argument("--skip-baseline", action="store_true", help="Skip unblocked baseline check")
    g.add_argument("--skip-port-block", action="store_true", help="Skip TCP port probes")
    g.add_argument("--skip-prolog", action="store_true", help="Skip no-bypass prolog curl")
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="blockcheckS - lightspeed DPI strategy tester")
    sub = parser.add_subparsers(dest="command", help="Commands")

    sub.add_parser(
        "full",
        help="Mass strategy×coverage test + nfqws2 conf export (see: bs full -h)",
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
    tcp.add_argument("--timeout", type=float, default=5.0)
    tcp.add_argument("--no-hostlist", action="store_true")
    tcp.add_argument("--qnum", type=int, default=200)
    tcp.add_argument("--ns")
    add_secure_dns_args(tcp)
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

    scan = sub.add_parser("scan", help="Async TCP strategy batch scan")
    scan.add_argument("-d", "--domain", default=None)
    scan.add_argument(
        "--generate",
        nargs="?",
        const="custom,configs",
        default="",
        help="Use matrix generator (sources: custom,configs,fake,faked,...)",
    )
    scan.add_argument("--preset", default=None, help="Domain preset name (presets/domains/{name}.txt)")
    scan.add_argument(
        "-M", "--strategy-preset", default=None, help="Strategy preset (presets/strategies/{name})"
    )
    scan.add_argument(
        "--disable-ech",
        action="store_true",
        help="Disable Encrypted Client Hello (force plaintext SNI)",
    )
    scan.add_argument("--list-presets", action="store_true", help="List available presets and exit")
    scan.add_argument(
        "--protocol",
        default="tls12",
        choices=["tls12", "tls13"],
        help="TLS protocol version to test",
    )
    scan.add_argument("--scan-level", default="fast", choices=["single", "fast", "full"])
    scan.add_argument("--parallel", type=int, default=4)
    scan.add_argument("--max", type=int, default=100)
    scan.add_argument("--timeout", type=float, default=5.0)
    scan.add_argument("--user-matrix", default="")
    add_store_args(scan)
    scan.add_argument(
        "--db-batch",
        type=int,
        default=0,
        metavar="N",
        help="Buffer N DB writes before flush (0=immediate, default)",
    )
    scan.add_argument("--resume", action="store_true")
    add_secure_dns_args(scan)
    add_curl_repeats_args(scan)
    add_family_gate_args(scan)
    add_domain_filter_args(scan)
    add_adaptive_args(scan)
    add_curl_fanout_args(scan)
    add_time_limit_args(scan, include_export=True)
    scan.add_argument("--export-limit", type=int, default=3)
    scan.add_argument(
        "--no-common-only",
        action="store_true",
        help="Export best per-domain instead of COMMON intersection",
    )
    scan.add_argument("--tcp-sources", default="")
    scan.add_argument("--ip", default="35.217.5.42", help=argparse.SUPPRESS)
    scan.add_argument("--port", type=int, default=50006, help=argparse.SUPPRESS)
    scan.add_argument("--udp-timeout", type=float, default=3.0, help=argparse.SUPPRESS)
    scan.add_argument("--udp-bypass", action="store_true", help=argparse.SUPPRESS)
    scan.add_argument(
        "--auto-discover", nargs="?", const=5, type=int, default=None, help=argparse.SUPPRESS
    )
    scan.add_argument("--full-voice", action="store_true", help=argparse.SUPPRESS)
    scan.add_argument(
        "--nfqws2-debug",
        nargs="?",
        const="1",
        default=None,
        help="nfqws2 --debug: 1=logs/file, syslog, or @path/path",
    )

    composite = sub.add_parser("composite", help="Test composite nfqws2 config")
    composite.add_argument("-c", "--config", required=True, help="Path to composite .conf file")
    composite.add_argument("-d", "--domains", nargs="+", help="Domains to test (default: Discord set)")
    composite.add_argument("--parallel", type=int, default=4)
    composite.add_argument("--timeout", type=float, default=5.0)

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
    pair.add_argument("--preset", default=None, help="Domain preset name (presets/domains/{name}.txt)")
    pair.add_argument(
        "--disable-ech",
        action="store_true",
        help="Disable Encrypted Client Hello (force plaintext SNI)",
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
    pair.add_argument("--parallel", type=int, default=4)
    pair.add_argument("--max", type=int, default=100)
    pair.add_argument("--timeout", type=float, default=5.0)
    pair.add_argument("--udp-timeout", type=float, default=3.0)
    pair.add_argument("--tcp-only", action="store_true", help="Skip UDP pair testing (TCP scan only)")
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
        default=0,
        metavar="N",
        help="Buffer N DB writes before flush (0=immediate, default)",
    )
    pair.add_argument("--resume", action="store_true")
    add_secure_dns_args(pair)
    add_curl_repeats_args(pair)
    add_family_gate_args(pair)
    add_domain_filter_args(pair)
    add_adaptive_args(pair)
    add_curl_fanout_args(pair)
    add_time_limit_args(pair, include_export=True)
    pair.add_argument("--export-limit", type=int, default=3)
    pair.add_argument(
        "--no-common-only",
        action="store_true",
        help="Export best per-domain instead of COMMON intersection",
    )
    pair.add_argument("--ns")
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

    return parser


def dispatch(args: argparse.Namespace) -> int:
    dbg = getattr(args, "nfqws2_debug", None)
    if dbg is not None:
        os.environ["BLOCKCHECKS_NFQWS2_DEBUG"] = str(dbg)

    if args.command == "tcp":
        return cmd_tcp(args)
    if args.command == "udp":
        return cmd_udp(args)
    if args.command == "scan":
        if getattr(args, "list_presets", False):
            list_presets()
            return 0
        if args.generate:
            args.tcp_sources = (
                args.generate
                if args.generate != "custom,configs"
                else args.tcp_sources or "custom,configs"
            )
        args.generate = bool(args.generate)
        args.tcp_only = True
        args.full_voice = False
        args.udp_bypass = False
        if not hasattr(args, "auto_discover") or args.auto_discover is False:
            args.auto_discover = None
        args.udp_sources = ""
        args.configs_dir = CONFIGS_DIR
        args.config = None
        args.udp_config = None
        return asyncio.run(cmd_pair(args))
    if args.command == "pair":
        if getattr(args, "list_presets", False):
            list_presets()
            return 0
        if args.generate and args.generate != "custom,configs":
            args.tcp_sources = args.generate
        if getattr(args, "config", None) or getattr(args, "udp_config", None):
            args.generate = False
        else:
            args.generate = bool(args.generate) or bool(
                getattr(args, "tcp_sources", "") != "custom,configs"
                or getattr(args, "udp_sources", "") != "custom"
            )
        return asyncio.run(cmd_pair(args))
    if args.command == "composite":
        from blockchecks.checkers.composite_runner import run as run_composite

        return asyncio.run(run_composite(args.config, args.domains, args.parallel, args.timeout))
    if args.command == "bench-settle":
        from blockchecks.cli.commands.bench_settle import cmd_bench_settle

        return asyncio.run(cmd_bench_settle(args))

    build_parser().print_help()
    return 1


def main(argv: list[str] | None = None) -> int:
    from blockchecks.cli.user_config import (
        apply_parser_defaults,
        finalize_store_args,
        load_user_config,
    )
    from blockchecks.engine.paths import apply_pycache_prefix, ensure_dirs

    apply_pycache_prefix()
    ensure_dirs()
    user_cfg = load_user_config()

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

    if args.command is None:
        parser.print_help()
        return 1
    finalize_store_args(args, user_cfg)
    from blockchecks.engine.run_deadline import validate_time_limit_args

    validate_time_limit_args(parser, args)
    return dispatch(args)
