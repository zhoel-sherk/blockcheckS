#!/usr/bin/env python3
"""blockcheckS — lightspeed DPI strategy tester.

Usage:
  # Single strategy
  sudo python3 bs.py tcp -d discord.com -s "fake:repeats=6:tcp_ts=-1000"
  sudo python3 bs.py tcp -d discord.com -c configs/simple_fake_alt2.conf

  # Batch from custom/ lists
  sudo python3 bs.py tcp -d discord.com --test custom --protocol tls12

  # Generate + async parallel
  sudo python3 bs.py scan -d discord.com --generate tls12 --parallel 4
  sudo python3 bs.py scan -d discord.com --generate tls12 --max 50 --scan-level fast

  # TCP×UDP pair matrix
  sudo python3 bs.py pair -d discord.com --generate --full-voice
  sudo python3 bs.py pair -d discord.com --user-matrix /path/to/strategies.txt

  # Resume after crash
  sudo python3 bs.py scan -d discord.com --resume
"""

import argparse
import asyncio
import os
import signal
import sys
import time
from typing import Optional

from colorama import Fore, Style, init as colorama_init
colorama_init(autoreset=True)

from blockchecks.engine.strategy_loader import StrategyLoader
from blockchecks.engine.test_runner import TestRunner
from blockchecks.engine.db_logger import StateDB, matrix_fingerprint
from blockchecks.engine.matrix_generator import MatrixGenerator, StrategyItem
from blockchecks.engine.async_runner import AsyncTestRunner
from blockchecks.engine.config import DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT, DPI_TESTER_SETTINGS, CONFIGS_DIR
from blockchecks.engine.config import PROJECT_DIR, CONFIGS_DIR

GREEN = Fore.GREEN + Style.BRIGHT
RED = Fore.RED + Style.BRIGHT
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
GREY = Fore.LIGHTBLACK_EX
RESET = Style.RESET_ALL


# ── Legacy synchronous TCP/UDP (unchanged) ──

def cmd_tcp(args):
    loader = StrategyLoader()
    mode = None
    if args.config:
        strategies = loader.from_config(args.config); mode = "config"
    elif args.configs_dir:
        strategies = loader.from_config_dir(args.configs_dir); mode = CONFIGS_DIR
    elif args.file:
        strategies = loader.from_file(args.file); mode = "string"
    elif args.strategy:
        strategies = loader.from_string(args.strategy); mode = "string"
    elif args.test == "custom":
        strategies = loader.from_custom_dir(args.test_dir, args.protocol)
        mode = "string"
    else:
        print("ERROR: specify --strategy, --config, --configs-dir, --file, or --test")
        return 1
    if not strategies:
        print("ERROR: no strategies loaded")
        return 1
    print(f"\n  blockcheckS — TCP TLS test")
    print(f"  Domain: {args.domain}  Items: {len(strategies)}  Timeout: {args.timeout}s\n")
    runner = TestRunner(ns_name=args.ns)
    if mode in (CONFIGS_DIR, "config") and strategies:
        report = runner.test_sequential_configs(strategies, args.domain, timeout=args.timeout, qnum=args.qnum)
    else:
        report = runner.test_sequential(strategies, args.domain, timeout=args.timeout,
                                         hostlist=[args.domain] if not args.no_hostlist else None, qnum=args.qnum)
    print(f"\n  Results: {report.passed}/{len(report.results)} passed ({report.total_time_sec:.1f}s)")
    return 0 if report.passed > 0 else 1


def cmd_udp(args):
    loader = StrategyLoader()
    if args.config: configs = loader.from_config(args.config); mode = "config"
    elif args.configs_dir: configs = loader.from_config_dir(args.configs_dir); mode = CONFIGS_DIR
    else: print("ERROR: specify --config or --configs-dir"); return 1
    if not configs: print("ERROR: no configs loaded"); return 1
    print(f"\n  blockcheckS — UDP Voice test")
    print(f"  Target: {args.ip}:{args.port}  Items: {len(configs)}  Timeout: {args.timeout}s\n")
    runner = TestRunner(ns_name=args.ns)
    report = runner.test_sequential_udp(configs, args.ip, port=args.port, timeout=args.timeout, qnum=args.qnum)
    print(f"\n  Results: {report.passed}/{len(report.results)} passed ({report.total_time_sec:.1f}s)")
    return 0 if report.passed > 0 else 1


# ── Async pair/scan ──

async def cmd_pair(args):
    """TCP×UDP pair matrix with generator + async runner."""
    db = StateDB(args.db)
    await db.init()

    if getattr(args, 'list_presets', False):
        _list_presets()
        return 0

    if not args.domain:
        print(f"{Fore.RED}ERROR: --domain required{RESET}")
        return 1

    pool_size = args.parallel or 4
    runner = AsyncTestRunner(pool_size=pool_size, db=db)
    stop_event = asyncio.Event()

    loop = asyncio.get_running_loop()

    def _request_stop():
        stop_event.set()

    try:
        loop.add_signal_handler(signal.SIGINT, _request_stop)
        loop.add_signal_handler(signal.SIGTERM, _request_stop)
    except (NotImplementedError, RuntimeError):
        # Windows: fallback
        signal.signal(signal.SIGINT, lambda *a: _request_stop())
        signal.signal(signal.SIGTERM, lambda *a: _request_stop())

    try:
        await runner.start()

        voice_ip = getattr(args, 'ip', None) or DEFAULT_VOICE_IP
        voice_port = getattr(args, 'port', None) or DEFAULT_VOICE_PORT
        gateway_result = None

        from blockchecks.checkers.voice_discovery import load_token
        token = load_token()
        has_token = bool(token)
        full_voice = args.full_voice and has_token

        auto_discover = getattr(args, 'auto_discover', None)
        multi_eps = []
        if auto_discover is not None:
            count = int(auto_discover)
            print(f"\n  {CYAN}Auto-discovering {count} voice endpoints...{RESET}")
            try:
                from blockchecks.checkers.voice_discovery import discover_multiple
                multi_eps = await discover_multiple(count, use_dns=True)
                if multi_eps:
                    for ep in multi_eps[:3]:
                        print(f"  {GREEN}  {ep['ip']}:{ep['port']} ({ep['hostname']}){RESET}")
                    if len(multi_eps) > 3:
                        print(f"  {GREEN}  ... and {len(multi_eps)-3} more{RESET}")
                    # Store all endpoints for multi-endpoint test
                    voice_ip = multi_eps[0]["ip"]
                    voice_port = multi_eps[0]["port"]
                else:
                    print(f"  {YELLOW}No endpoints found — using static{RESET}")
            except Exception as e:
                print(f"  {YELLOW}Discovery error: {e}{RESET}")

        if args.full_voice and not has_token:
            print(f"  {YELLOW}No Discord token. --full-voice → STUN only{RESET}")
            print(f"  Add token to {DPI_TESTER_SETTINGS}")

        if full_voice:
            print(f"  {CYAN}Full-voice mode: discovery+STUN "
                  f"(gateway WS probe not implemented){RESET}")

        # Resolve domain preset
        preset_domains = []
        preset_name = getattr(args, 'preset', None)
        if preset_name:
            preset_path = os.path.join(PROJECT_DIR, "presets", "domains", f"{preset_name}.txt")
            if os.path.exists(preset_path):
                with open(preset_path) as pf:
                    preset_domains = [l.strip() for l in pf if l.strip() and not l.startswith("#")]
                print(f"  {Fore.CYAN}Preset '{preset_name}': {len(preset_domains)} domains{RESET}")
            else:
                print(f"  {Fore.YELLOW}Preset '{preset_name}' not found. Available:{RESET}")
                import glob
                for f in sorted(glob.glob(os.path.join(PROJECT_DIR, "presets/domains", "*.txt"))):
                    print(f"    {os.path.basename(f).replace('.txt','')}")
                return 1

        # Resolve strategy preset (-M flag)
        strategy_preset = getattr(args, 'strategy_preset', None)
        if strategy_preset:
            for ext in ['.tls', '.txt']:
                sp = os.path.join(PROJECT_DIR, "presets", "strategies", f"{strategy_preset}{ext}")
                if os.path.exists(sp):
                    args.user_matrix = sp
                    break
            else:
                print(f"  {Fore.YELLOW}Strategy preset '{strategy_preset}' not found{RESET}")

        do_generate = getattr(args, 'generate', False)
        user_matrix = getattr(args, 'user_matrix', '') or ""
        run_set: set = set()
        tcp_items = []
        udp_items = []

        # -c / -u single configs
        if getattr(args, 'config', None):
            tcp_items = [StrategyItem(
                label=os.path.basename(args.config).replace(".conf", ""),
                strategy=args.config, is_config=True)]
            do_generate = False
        if getattr(args, 'udp_config', None):
            udp_items = [StrategyItem(
                label=os.path.basename(args.udp_config).replace(".conf", ""),
                strategy=args.udp_config, is_config=True)]

        if do_generate or user_matrix:
            scanner = MatrixGenerator()
            tcp_src = getattr(args, 'tcp_sources', '') or "custom,configs"
            udp_src = getattr(args, 'udp_sources', '') or "custom"
            # scan tcp_only: don't generate unused UDP
            if getattr(args, 'tcp_only', False):
                udp_src = ""
            tcp_sources = [s for s in tcp_src.split(",") if s]
            udp_sources = [s for s in udp_src.split(",") if s]

            print(f"\n  {CYAN}Generating strategies...{RESET}")
            if not tcp_items:
                tcp_items = await scanner.generate_tcp(
                    sources=tcp_sources or ["custom", CONFIGS_DIR],
                    domain=args.domain,
                    scan_level=getattr(args, 'scan_level', 'fast'),
                    max_count=getattr(args, 'max', 100),
                    state_db=db, user_matrix=user_matrix,
                    run_set=run_set,
                )
            if not udp_items and udp_sources and not args.tcp_only:
                udp_items = await scanner.generate_udp(
                    sources=udp_sources, domain=args.domain,
                    scan_level=args.scan_level,
                    max_count=max(1, args.max // 2) if args.max >= 2 else 50,
                    state_db=db, user_matrix=user_matrix,
                )
            print(f"  Generated: {len(tcp_items)} TCP + {len(udp_items)} UDP strategies")
        elif not tcp_items:
            loader = StrategyLoader()
            tcp_configs = loader.from_config_dir(args.configs_dir or CONFIGS_DIR)
            tcp_items = [StrategyItem(label=os.path.basename(c).replace(".conf", ""),
                                       strategy=c, is_config=True)
                          for c in tcp_configs if "udp_voice" not in c.lower()]
            if not udp_items:
                udp_items = [StrategyItem(label=os.path.basename(c).replace(".conf", ""),
                                           strategy=c, is_config=True)
                              for c in tcp_configs if "udp_voice" in c.lower()]

        print(f"\n  {CYAN}blockcheckS — {'Pair Matrix' if not args.tcp_only else 'TCP Scan'}{RESET}")
        print(f"  Domain:     {args.domain}")
        print(f"  TCP:        {len(tcp_items)} strategies")
        print(f"  UDP:        {len(udp_items)} strategies")
        print(f"  Voice:      {voice_ip}:{voice_port}")
        if not tcp_items:
            print(f"  ERROR: no strategies loaded")
            return 1
        print(f"  Full Voice: {'discovery+STUN' if full_voice else 'STUN only'}")
        print(f"  UDP Bypass: {'yes' if args.udp_bypass else 'no'}")
        print(f"  Workers:    {pool_size}")
        print(f"  DB:         {args.db}")

        fp = matrix_fingerprint(
            [i.strategy for i in tcp_items],
            [i.strategy for i in udp_items],
            getattr(args, 'scan_level', 'fast'),
            getattr(args, 'max', 100),
        )
        runner.matrix_fingerprint = fp

        resume_from = None
        if args.resume:
            resume_from = await db.latest_checkpoint()
            if resume_from:
                if resume_from.fingerprint and resume_from.fingerprint != fp:
                    print(f"  {RED}ERROR: matrix changed, refuse --resume; start fresh{RESET}")
                    print(f"  checkpoint fp={resume_from.fingerprint} current fp={fp}")
                    return 1
                print(f"  {YELLOW}Resuming after "
                      f"{resume_from.tcp_label}+{resume_from.udp_label}{RESET}")
            else:
                print(f"  {YELLOW}No checkpoint found — starting fresh{RESET}")

        if stop_event.is_set():
            return 130

        t0 = time.perf_counter()

        print(f"\n  {CYAN}[TCP Phase]{RESET} {len(tcp_items)} strategies...")
        tcp_results = await runner.test_batch_tcp(tcp_items, args.domain, args.timeout)

        tcp_passed = sum(1 for r in tcp_results if r.success)
        print(f"\n  TCP: {GREEN}{tcp_passed}{RESET}/{len(tcp_results)} passed")

        for r in tcp_results:
            if r.success:
                run_set.add(r.item.label)

        pairs = []
        if not args.tcp_only and udp_items:
            if stop_event.is_set():
                return 130
            print(f"\n  {CYAN}[UDP Pairs]{RESET} {len(udp_items)} strategies...")
            pairs = await runner.test_pair_matrix(
                tcp_results, udp_items, args.domain,
                voice_ip, voice_port,
                udp_timeout=args.udp_timeout,
                udp_bypass=args.udp_bypass,
                resume_from=resume_from,
                full_voice=full_voice,
                fingerprint=fp,
            )
            AsyncTestRunner.print_matrix(pairs)

        elapsed = time.perf_counter() - t0
        print(f"\n  {CYAN}Done in {elapsed:.0f}s{RESET}")
        if tcp_passed <= 0:
            return 1
        if pairs and not any(p.overall == "PASS" for p in pairs) and not args.tcp_only:
            return 1
        return 0

    finally:
        await runner.stop()


# ── CLI ──

def main():
    parser = argparse.ArgumentParser(
        description="blockcheckS - lightspeed DPI strategy tester")
    sub = parser.add_subparsers(dest="command", help="Commands")

    # tcp — legacy synchronous
    tcp = sub.add_parser("tcp", help="Single TCP strategy test (sync)")
    tcp.add_argument("-d", "--domain", required=True)
    tcp.add_argument("-s", "--strategy")
    tcp.add_argument("-c", "--config")
    tcp.add_argument("-C", "--configs-dir")
    tcp.add_argument("-f", "--file")
    tcp.add_argument("--test", choices=["custom", "standard"])
    tcp.add_argument("--test-dir", default="/opt/zapret2/blockcheck2.d")
    tcp.add_argument("--protocol", default="tls12",
                     choices=["http", "tls12", "tls13", "quic", "udp_voice"])
    tcp.add_argument("--timeout", type=float, default=5.0)
    tcp.add_argument("--no-hostlist", action="store_true")
    tcp.add_argument("--qnum", type=int, default=200)
    tcp.add_argument("--ns")

    # udp — legacy synchronous
    udp = sub.add_parser("udp", help="Single UDP strategy test (sync)")
    udp.add_argument("-c", "--config")
    udp.add_argument("-C", "--configs-dir")
    udp.add_argument("--ip", default=DEFAULT_VOICE_IP)
    udp.add_argument("--port", type=int, default=DEFAULT_VOICE_PORT)
    udp.add_argument("--timeout", type=float, default=3.0)
    udp.add_argument("--qnum", type=int, default=201)
    udp.add_argument("--ns")

    # scan — async TCP batch (alias to pair --tcp-only)
    scan = sub.add_parser("scan", help="Async TCP strategy batch scan")
    scan.add_argument("-d", "--domain", default=None)
    scan.add_argument("--generate", nargs="?", const="custom,configs",
                      default="", help="Use matrix generator (sources: custom,configs,fake,faked,...)")
    scan.add_argument("--preset", default=None, help="Domain preset name (presets/domains/{name}.txt)")
    scan.add_argument("-M", "--strategy-preset", default=None, help="Strategy preset (presets/strategies/{name})")
    scan.add_argument("--list-presets", action="store_true", help="List available presets and exit")
    scan.add_argument("--protocol", default="tls12", choices=["tls12", "tls13"], help="TLS protocol version to test")
    scan.add_argument("--scan-level", default="fast", choices=["single", "fast", "full"])
    scan.add_argument("--parallel", type=int, default=4)
    scan.add_argument("--max", type=int, default=100)
    scan.add_argument("--timeout", type=float, default=5.0)
    scan.add_argument("--user-matrix", default="")
    scan.add_argument("--db", default="state.db")
    scan.add_argument("--resume", action="store_true")
    scan.add_argument("--tcp-sources", default="")
    scan.add_argument("--ip", default="35.217.5.42", help=argparse.SUPPRESS)
    scan.add_argument("--port", type=int, default=50006, help=argparse.SUPPRESS)
    scan.add_argument("--udp-timeout", type=float, default=3.0, help=argparse.SUPPRESS)
    scan.add_argument("--udp-bypass", action="store_true", help=argparse.SUPPRESS)
    scan.add_argument("--auto-discover", nargs="?", const=5, type=int, default=None, help=argparse.SUPPRESS)
    scan.add_argument("--full-voice", action="store_true", help=argparse.SUPPRESS)

    # composite — single config, multiple domains
    composite = sub.add_parser("composite", help="Test composite nfqws2 config")
    composite.add_argument("-c", "--config", required=True,
                           help="Path to composite .conf file")
    composite.add_argument("-d", "--domains", nargs="+",
                           help="Domains to test (default: Discord set)")
    composite.add_argument("--parallel", type=int, default=4)
    composite.add_argument("--timeout", type=float, default=5.0)

    # pair — async TCP×UDP matrix
    pair = sub.add_parser("pair", help="TCP x UDP pair matrix (async)")
    pair.add_argument("-d", "--domain", default=None)
    pair.add_argument("--generate", nargs="?", const="custom,configs",
                      default="", help="Use matrix generator")
    pair.add_argument("--tcp-sources", default="custom,configs",
                      help="TCP sources: custom,configs,fake,faked,hostfake,fake_multi,fake_faked")
    pair.add_argument("--udp-sources", default="custom",
                      help="UDP sources: custom,configs")
    pair.add_argument("--preset", default=None, help="Domain preset name (presets/domains/{name}.txt)")
    pair.add_argument("--list-presets", action="store_true", help="List available presets and exit")
    pair.add_argument("-M", "--strategy-preset", default=None, help="Strategy preset (presets/strategies/{name})")
    pair.add_argument("--protocol", default="tls12", choices=["tls12", "tls13"], help="TLS protocol version to test")
    pair.add_argument("--scan-level", default="fast", choices=["single", "fast", "full"])
    pair.add_argument("--parallel", type=int, default=4)
    pair.add_argument("--max", type=int, default=100)
    pair.add_argument("--timeout", type=float, default=5.0)
    pair.add_argument("--udp-timeout", type=float, default=3.0)
    pair.add_argument("--tcp-only", action="store_true",
                      help="Skip UDP pair testing (TCP scan only)")
    pair.add_argument("-c", "--config", help="Single TCP .conf file")
    pair.add_argument("-u", "--udp-config", help="Single UDP .conf file")
    pair.add_argument("-C", "--configs-dir", default=CONFIGS_DIR)
    pair.add_argument("--ip", default=DEFAULT_VOICE_IP)
    pair.add_argument("--port", type=int, default=DEFAULT_VOICE_PORT)
    pair.add_argument("--auto-discover", nargs="?", const=5, type=int, default=None)
    pair.add_argument("--full-voice", action="store_true")
    pair.add_argument("--udp-bypass", action="store_true")
    pair.add_argument("--user-matrix", default="",
                      help="Path to custom strategy list file")
    pair.add_argument("--db", default="state.db")
    pair.add_argument("--resume", action="store_true")
    pair.add_argument("--ns")

    args = parser.parse_args()

    if args.command == "tcp":
        return cmd_tcp(args)
    elif args.command == "udp":
        return cmd_udp(args)
    elif args.command == "scan":
        if getattr(args, 'list_presets', False):
            _list_presets()
            return 0
        # Alias to pair --tcp-only
        if args.generate:
            args.tcp_sources = args.generate if args.generate != "custom,configs" else args.tcp_sources or "custom,configs"
        args.generate = bool(args.generate)
        args.tcp_only = True
        args.full_voice = False
        args.udp_bypass = False
        args.auto_discover = False
        args.udp_sources = ""
        args.configs_dir = CONFIGS_DIR
        args.config = None
        args.udp_config = None
        if args.user_matrix:
            pass
        return asyncio.run(cmd_pair(args))
    elif args.command == "pair":
        if getattr(args, 'list_presets', False):
            _list_presets()
            return 0
        if args.generate and args.generate != "custom,configs":
            args.tcp_sources = args.generate
        # Single config flags (-c/-u) force non-generate path
        if getattr(args, 'config', None) or getattr(args, 'udp_config', None):
            args.generate = False
        else:
            args.generate = bool(args.generate) or bool(getattr(args, 'tcp_sources', '') != "custom,configs"
                                                         or getattr(args, 'udp_sources', '') != "custom")
        return asyncio.run(cmd_pair(args))
    elif args.command == "composite":
        from blockchecks.checkers.composite_runner import run as run_composite
        return asyncio.run(run_composite(
            args.config, args.domains, args.parallel, args.timeout
        ))
    else:
        parser.print_help()
        return 1


def _list_presets():
    """Print available domain and strategy presets."""
    import glob, os
    print(f"{Fore.CYAN}Domain presets (presets/domains/):{RESET}")
    for f in sorted(glob.glob(os.path.join(PROJECT_DIR, "presets/domains", "*.txt"))):
        name = os.path.basename(f).replace(".txt", "")
        with open(f) as pf:
            count = sum(1 for l in pf if l.strip() and not l.startswith("#"))
        print(f"  {name:25s} {count} domains")
    print(f"{Fore.CYAN}Strategy presets (presets/strategies/):{RESET}")
    for f in sorted(glob.glob(os.path.join(PROJECT_DIR, "presets/strategies", "*.tls")) + glob.glob(os.path.join(PROJECT_DIR, "presets/strategies", "*.txt"))):
        name = os.path.basename(f)
        with open(f) as pf:
            count = sum(1 for l in pf if l.strip() and not l.startswith("#"))
        print(f"  {name:25s} {count} strategies")


if __name__ == "__main__":
    sys.exit(main())
