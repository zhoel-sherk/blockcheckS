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
    scan.add_argument("--db", default="state.db")
    scan.add_argument("--resume", action="store_true")
    add_secure_dns_args(scan)
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
        help="TCP sources: custom,configs,fake,faked,hostfake,fake_multi,fake_faked",
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
    pair.add_argument("--db", default="state.db")
    pair.add_argument("--resume", action="store_true")
    add_secure_dns_args(pair)
    pair.add_argument("--ns")
    pair.add_argument(
        "--nfqws2-debug",
        nargs="?",
        const="1",
        default=None,
        help="nfqws2 --debug: 1=logs/file, syslog, or @path/path",
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

    build_parser().print_help()
    return 1


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) > 0 and argv[0] == "full":
        from blockchecks.main import main as full_main

        return full_main(argv[1:])

    old_argv = sys.argv
    try:
        sys.argv = ["bs", *argv]
        args = build_parser().parse_args(argv)
    finally:
        sys.argv = old_argv

    if args.command is None:
        build_parser().print_help()
        return 1
    return dispatch(args)
