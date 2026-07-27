#!/usr/bin/env python3
"""blockcheckS — lightspeed DPI strategy tester.

Usage:
  # Single TCP strategy
  sudo python3 bs.py tcp -d discord.com -s "fake:repeats=6:tcp_ts=-1000"
  sudo python3 bs.py tcp -d discord.com -c configs/simple_fake_alt2.conf
  sudo python3 bs.py tcp -d discord.com -C configs/

  # Single UDP strategy
  sudo python3 bs.py udp -c configs/udp_voice__fake_r6.conf --ip 35.217.5.42

  # TCP×UDP pair matrix
  sudo python3 bs.py pair -d discord.com -C configs/
  sudo python3 bs.py pair -d discord.com -C configs/ --auto-discover --full-voice
  sudo python3 bs.py pair -d discord.com -C configs/ --resume
"""

import argparse
import asyncio
import os
import sys
import time

from colorama import Fore, Style, init as colorama_init
colorama_init(autoreset=True)

from engine.strategy_loader import StrategyLoader
from engine.test_runner import TestRunner
from engine.pair_runner import PairTestRunner
from engine.db_logger import StateDB

GREEN = Fore.GREEN + Style.BRIGHT
RED = Fore.RED + Style.BRIGHT
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
RESET = Style.RESET_ALL


def cmd_tcp(args):
    loader = StrategyLoader()
    mode = None

    if args.config:
        strategies = loader.from_config(args.config)
        mode = "config"
    elif args.configs_dir:
        strategies = loader.from_config_dir(args.configs_dir)
        mode = "configs"
    elif args.file:
        strategies = loader.from_file(args.file)
        mode = "string"
    elif args.strategy:
        strategies = loader.from_string(args.strategy)
        mode = "string"
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
    print(f"  Domain:     {args.domain}")
    print(f"  Mode:       {mode}")
    print(f"  Items:      {len(strategies)}")
    print(f"  Timeout:    {args.timeout}s\n")

    runner = TestRunner(ns_name=args.ns)

    if mode in ("configs", "config") and strategies:
        report = runner.test_sequential_configs(
            strategies, args.domain, timeout=args.timeout, qnum=args.qnum
        )
    else:
        report = runner.test_sequential(
            strategies, args.domain, timeout=args.timeout,
            hostlist=[args.domain] if not args.no_hostlist else None,
            qnum=args.qnum,
        )

    print(f"\n  Results: {report.passed}/{len(report.results)} passed "
          f"({report.total_time_sec:.1f}s)")
    return 0 if report.passed > 0 else 1


def cmd_udp(args):
    loader = StrategyLoader()
    mode = None

    if args.config:
        configs = loader.from_config(args.config)
        mode = "config"
    elif args.configs_dir:
        configs = loader.from_config_dir(args.configs_dir)
        mode = "configs"
    else:
        print("ERROR: specify --config or --configs-dir")
        return 1

    if not configs:
        print("ERROR: no configs loaded")
        return 1

    print(f"\n  blockcheckS — UDP Voice test")
    print(f"  Target:     {args.ip}:{args.port}")
    print(f"  Mode:       {mode}")
    print(f"  Configs:    {len(configs)}")
    print(f"  Timeout:    {args.timeout}s\n")

    runner = TestRunner(ns_name=args.ns)
    report = runner.test_sequential_udp(
        configs, args.ip, port=args.port, timeout=args.timeout, qnum=args.qnum
    )

    print(f"\n  Results: {report.passed}/{len(report.results)} passed "
          f"({report.total_time_sec:.1f}s)")
    return 0 if report.passed > 0 else 1


async def cmd_pair(args):
    """TCP×UDP pair matrix testing."""
    loader = StrategyLoader()

    # Load TCP configs
    if args.tcp_config:
        tcp_configs = loader.from_config(args.tcp_config)
    elif args.tcp_dir:
        tcp_configs = loader.from_config_dir(args.tcp_dir)
    elif args.configs_dir:
        tcp_configs = [c for c in loader.from_config_dir(args.configs_dir)
                       if "udp_voice" not in c.lower()]
    else:
        tcp_configs = [c for c in loader.from_config_dir("configs")
                       if "udp_voice" not in c.lower()]

    # Load UDP configs
    if args.udp_config:
        udp_configs = loader.from_config(args.udp_config)
    elif args.udp_dir:
        udp_configs = loader.from_config_dir(args.udp_dir)
    elif args.configs_dir:
        udp_configs = [c for c in loader.from_config_dir(args.configs_dir)
                       if "udp_voice" in c.lower()]
    else:
        udp_configs = [c for c in loader.from_config_dir("configs")
                       if "udp_voice" in c.lower()]

    if not udp_configs:
        print(f"  {YELLOW}No UDP configs found — skipping UDP matrix{RESET}")
        print(f"  Create UDP configs in configs/ (e.g., udp_voice__*.conf)")

    if not tcp_configs:
        print("ERROR: no TCP configs loaded")
        return 1

    # Voice target
    voice_ip = args.ip or "35.217.5.42"
    voice_port = args.port or 50006
    voice_info = {}

    # Auto-discovery
    if args.auto_discover:
        print(f"\n  {CYAN}Auto-discovering voice endpoint via sing-box...{RESET}")
        from checkers.voice_discovery import discover_voice_endpoint
        voice_info = await discover_voice_endpoint()
        if voice_info:
            voice_ip = voice_info["ip"]
            voice_port = voice_info["port"]
            print(f"  {GREEN}Discovered: {voice_ip}:{voice_port}{RESET}")
        else:
            print(f"  {YELLOW}Auto-discovery failed. Using: {voice_ip}:{voice_port}{RESET}")

    # Token check
    from checkers.voice_discovery import load_token
    token = load_token()
    has_token = bool(token)
    full_voice = args.full_voice and has_token

    if args.full_voice and not has_token:
        print(f"  {YELLOW}No Discord token found. --full-voice → SKIP (using STUN probe){RESET}")
        print(f"  Add token to ~/workspace/dpi-tester/settings.ini for full voice testing.")

    print(f"\n  {CYAN}blockcheckS — TCP×UDP Pair Matrix{RESET}")
    print(f"  Domain:     {args.domain}")
    print(f"  TCP configs:{len(tcp_configs)}")
    print(f"  UDP configs:{len(udp_configs)}")
    print(f"  Voice:      {voice_ip}:{voice_port}")
    print(f"  Full Voice: {'yes' if full_voice else 'STUN only'}")
    print(f"  UDP Bypass: {'yes' if args.udp_bypass else 'no (only PASS TCP)'}")
    print(f"  DB:         {args.db}")

    # Init DB
    db = StateDB(args.db)
    await db.init()

    runner = PairTestRunner(ns_name=args.ns, db_path=args.db)

    # Handle --resume
    resume_from = None
    if args.resume:
        resume_from = await db.latest_checkpoint()
        if resume_from:
            print(f"  {YELLOW}Resuming from checkpoint: tcp={resume_from[0]} udp={resume_from[1]} ({resume_from[2]}){RESET}")
        else:
            print(f"  {YELLOW}No checkpoint found — starting from beginning{RESET}")

    t0 = time.perf_counter()

    # ── TCP phase ──
    print(f"\n  {CYAN}[TCP Phase]{RESET} Testing {len(tcp_configs)} strategies...")
    tcp_results = await runner.test_tcp_matrix(tcp_configs, args.domain, args.timeout)

    tcp_passed = sum(1 for r in tcp_results if r.success)
    print(f"\n  TCP: {GREEN}{tcp_passed}{RESET}/{len(tcp_results)} passed")

    # ── UDP pairs ──
    if udp_configs:
        print(f"\n  {CYAN}[UDP Pair Matrix]{RESET} ({len(udp_configs)} UDP strategies)...")
        report = await runner.test_pair_matrix(
            tcp_configs, udp_configs, args.domain,
            tcp_results, voice_ip, voice_port,
            udp_timeout=args.udp_timeout,
            udp_bypass=args.udp_bypass,
            resume_from=resume_from,
        )
        runner.print_matrix(report)
    else:
        print(f"\n  {YELLOW}No UDP configs — pair matrix skipped{RESET}")

    elapsed = time.perf_counter() - t0
    print(f"\n  {CYAN}Done in {elapsed:.0f}s{RESET}")

    # Show working pairs
    passing = await db.get_passing_pairs(args.domain)
    if passing:
        print(f"\n  {GREEN}Working pairs ({len(passing)}):{RESET}")
        for p in passing:
            print(f"  {p['tcp']:30s} + {p['udp']:30s}  "
                  f"tcp={p['tcp_ms']:.0f}ms  udp={p['udp_ms']:.0f}ms")

    return 0


def main():
    parser = argparse.ArgumentParser(description="blockcheckS — lightspeed DPI strategy tester")
    sub = parser.add_subparsers(dest="command", help="Commands")

    # tcp command
    tcp = sub.add_parser("tcp", help="Test TCP TLS strategies")
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

    # udp command
    udp = sub.add_parser("udp", help="Test UDP voice strategies (STUN probe)")
    udp.add_argument("-c", "--config")
    udp.add_argument("-C", "--configs-dir")
    udp.add_argument("--ip", default="35.217.31.203")
    udp.add_argument("--port", type=int, default=50004)
    udp.add_argument("--timeout", type=float, default=3.0)
    udp.add_argument("--qnum", type=int, default=201)
    udp.add_argument("--ns")

    # pair command
    pair = sub.add_parser("pair", help="TCP×UDP pair matrix testing")
    pair.add_argument("-d", "--domain", required=True,
                      help="Domain for TCP test (default: discord.com)")
    pair.add_argument("-t", "--tcp-config",
                      help="Single TCP .conf file")
    pair.add_argument("-u", "--udp-config",
                      help="Single UDP .conf file")
    pair.add_argument("--tcp-dir",
                      help="Directory with TCP .conf files")
    pair.add_argument("--udp-dir",
                      help="Directory with UDP .conf files")
    pair.add_argument("-C", "--configs-dir", default="configs",
                      help="Directory with all .conf files (default: configs/)")
    pair.add_argument("--ip", default="35.217.5.42",
                      help="Voice server IP for UDP probe")
    pair.add_argument("--port", type=int, default=50006,
                      help="Voice server port for UDP probe")
    pair.add_argument("--udp-timeout", type=float, default=3.0,
                      help="UDP probe timeout (default: 3s)")
    pair.add_argument("--timeout", type=float, default=5.0,
                      help="TCP TLS timeout (default: 5s)")
    pair.add_argument("--auto-discover", action="store_true",
                      help="Auto-discover voice IP via sing-box proxy")
    pair.add_argument("--full-voice", action="store_true",
                      help="Full WebSocket handshake (requires Discord token)")
    pair.add_argument("--udp-bypass", action="store_true",
                      help="Test UDP on FAIL TCP strategies too")
    pair.add_argument("--db", default="state.db",
                      help="SQLite state DB path (default: state.db)")
    pair.add_argument("--resume", action="store_true",
                      help="Resume from last checkpoint in state.db")
    pair.add_argument("--ns",
                      help="Run inside network namespace")

    args = parser.parse_args()

    if args.command == "tcp":
        return cmd_tcp(args)
    elif args.command == "udp":
        return cmd_udp(args)
    elif args.command == "pair":
        return asyncio.run(cmd_pair(args))
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
