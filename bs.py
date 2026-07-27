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

from engine.strategy_loader import StrategyLoader
from engine.test_runner import TestRunner
from engine.db_logger import StateDB
from engine.matrix_generator import MatrixGenerator, StrategyItem
from engine.async_runner import AsyncTestRunner

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
        strategies = loader.from_config_dir(args.configs_dir); mode = "configs"
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
    if mode in ("configs", "config") and strategies:
        report = runner.test_sequential_configs(strategies, args.domain, timeout=args.timeout, qnum=args.qnum)
    else:
        report = runner.test_sequential(strategies, args.domain, timeout=args.timeout,
                                         hostlist=[args.domain] if not args.no_hostlist else None, qnum=args.qnum)
    print(f"\n  Results: {report.passed}/{len(report.results)} passed ({report.total_time_sec:.1f}s)")
    return 0 if report.passed > 0 else 1


def cmd_udp(args):
    loader = StrategyLoader()
    if args.config: configs = loader.from_config(args.config); mode = "config"
    elif args.configs_dir: configs = loader.from_config_dir(args.configs_dir); mode = "configs"
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

    # Prepare runner + pool
    pool_size = args.parallel or 4
    runner = AsyncTestRunner(pool_size=pool_size, db=db)
    await runner.start()

    # Register signal handlers for clean shutdown
    def cleanup():
        try: asyncio.get_event_loop().create_task(runner.stop())
        except: pass
    signal.signal(signal.SIGINT, lambda *a: (cleanup(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda *a: (cleanup(), sys.exit(0)))

    try:
        # Voice target
        voice_ip = getattr(args, 'ip', None) or "35.217.5.42"
        voice_port = getattr(args, 'port', None) or 50006
        gateway_result = None  # for --full-voice

        # Token check
        from checkers.voice_discovery import load_token
        token = load_token()
        has_token = bool(token)
        full_voice = args.full_voice and has_token

        # Auto-discovery / --full-voice
        if args.auto_discover or (full_voice and has_token):
            if not has_token and args.auto_discover:
                print(f"\n  {YELLOW}No token — auto-discover needs token, using static IP{RESET}")
            else:
                print(f"\n  {CYAN}Auto-discovering voice endpoint via sing-box...{RESET}")
                try:
                    from checkers.voice_discovery import discover_voice_endpoint
                    voice_info = await discover_voice_endpoint()
                    if voice_info:
                        voice_ip = voice_info["ip"]
                        voice_port = voice_info["port"]
                        gateway_result = {"endpoint": voice_info.get("voice_ws_endpoint", ""),
                                          "ssrc": voice_info.get("ssrc", 0),
                                          "ip": voice_ip, "port": voice_port}
                        print(f"  {GREEN}Discovered: {voice_ip}:{voice_port} "
                              f"(SSRC={gateway_result['ssrc']}){RESET}")
                        print(f"  {GREEN}Gateway: {gateway_result['endpoint']}{RESET}")
                    else:
                        print(f"  {YELLOW}Auto-discovery failed. Using: {voice_ip}:{voice_port}{RESET}")
                        if full_voice:
                            full_voice = False
                except Exception as e:
                    print(f"  {YELLOW}Discovery error: {e} — using static IP{RESET}")
                    if full_voice:
                        full_voice = False

        if args.full_voice and not has_token:
            print(f"  {YELLOW}No Discord token. --full-voice → SKIP (STUN probe only){RESET}")
            print(f"  Add token to ~/workspace/dpi-tester/settings.ini for full voice testing.")

        # Generate or load strategies
        do_generate = getattr(args, 'generate', False)
        if do_generate:
            scanner = MatrixGenerator()
            tcp_src = getattr(args, 'tcp_sources', '') or "custom,configs"
            udp_src = getattr(args, 'udp_sources', '') or "custom"
            tcp_sources = tcp_src.split(",")
            udp_sources = udp_src.split(",")
            user_matrix = getattr(args, 'user_matrix', '') or ""

            print(f"\n  {CYAN}Generating strategies...{RESET}")
            tcp_items = await scanner.generate_tcp(
                sources=tcp_sources, domain=args.domain,
                scan_level=getattr(args, 'scan_level', 'fast'),
                max_count=getattr(args, 'max', 100),
                state_db=db, user_matrix=user_matrix,
            )
            udp_items = await scanner.generate_udp(
                sources=udp_sources, domain=args.domain,
                scan_level=args.scan_level, max_count=args.max // 2 or 50,
                state_db=db, user_matrix=user_matrix,
            )
            print(f"  Generated: {len(tcp_items)} TCP + {len(udp_items)} UDP strategies")
        else:
            # Legacy: load from configs
            loader = StrategyLoader()
            tcp_configs = loader.from_config_dir(args.configs_dir or "configs")
            tcp_items = [StrategyItem(label=os.path.basename(c).replace(".conf", ""),
                                       strategy=c, is_config=True)
                          for c in tcp_configs if "udp_voice" not in c.lower()]
            udp_configs = [c for c in tcp_configs if "udp_voice" in c.lower()]
            if not udp_configs:
                udp_configs = loader.from_config_dir(args.configs_dir or "configs")
            udp_items = [StrategyItem(label=os.path.basename(c).replace(".conf", ""),
                                       strategy=c, is_config=True)
                          for c in udp_configs if "udp_voice" in c.lower()]

        print(f"\n  {CYAN}blockcheckS — {'Pair Matrix' if not args.tcp_only else 'TCP Scan'}{RESET}")
        print(f"  Domain:     {args.domain}")
        print(f"  TCP:        {len(tcp_items)} strategies")
        print(f"  UDP:        {len(udp_items)} strategies")
        print(f"  Voice:      {voice_ip}:{voice_port}")
        print(f"  Full Voice: {'yes' if full_voice else 'STUN only'}")
        print(f"  UDP Bypass: {'yes' if args.udp_bypass else 'no'}")
        print(f"  Workers:    {pool_size}")
        print(f"  DB:         {args.db}")

        # Resume
        resume_from = None
        if args.resume:
            resume_from = await db.latest_checkpoint()
            if resume_from:
                print(f"  {YELLOW}Resuming: tcp={resume_from[0]} udp={resume_from[1]}{RESET}")

        t0 = time.perf_counter()

        # ── TCP phase ──
        print(f"\n  {CYAN}[TCP Phase]{RESET} {len(tcp_items)} strategies...")
        tcp_results = await runner.test_batch_tcp(tcp_items, args.domain, args.timeout)

        tcp_passed = sum(1 for r in tcp_results if r.success)
        print(f"\n  TCP: {GREEN}{tcp_passed}{RESET}/{len(tcp_results)} passed")

        # ── UDP pairs (skip if tcp-only) ──
        if not args.tcp_only and udp_items:
            print(f"\n  {CYAN}[UDP Pairs]{RESET} {len(udp_items)} strategies...")
            pairs = await runner.test_pair_matrix(
                tcp_results, udp_items, args.domain,
                voice_ip, voice_port,
                udp_timeout=args.udp_timeout,
                udp_bypass=args.udp_bypass,
            )
            AsyncTestRunner.print_matrix(pairs)

        elapsed = time.perf_counter() - t0
        print(f"\n  {CYAN}Done in {elapsed:.0f}s{RESET}")
        tcp_passed_local = sum(1 for r in tcp_results if r.success) if "tcp_results" in dir() else 0
        return 0 if tcp_passed_local > 0 else 1

    finally:
        await runner.stop()


# ── CLI ──

def main():
    parser = argparse.ArgumentParser(description="blockcheckS — lightspeed DPI strategy tester")
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
    udp.add_argument("--ip", default="35.217.31.203")
    udp.add_argument("--port", type=int, default=50004)
    udp.add_argument("--timeout", type=float, default=3.0)
    udp.add_argument("--qnum", type=int, default=201)
    udp.add_argument("--ns")

    # scan — async TCP batch (alias to pair --tcp-only)
    scan = sub.add_parser("scan", help="Async TCP strategy batch scan")
    scan.add_argument("-d", "--domain", required=True)
    scan.add_argument("--generate", nargs="?", const="custom,configs",
                      default="", help="Use matrix generator (sources: custom,configs,fake,faked,...)")
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
    scan.add_argument("--auto-discover", action="store_true", help=argparse.SUPPRESS)
    scan.add_argument("--full-voice", action="store_true", help=argparse.SUPPRESS)

    # pair — async TCP×UDP matrix
    pair = sub.add_parser("pair", help="TCP×UDP pair matrix (async)")
    pair.add_argument("-d", "--domain", required=True)
    pair.add_argument("--generate", nargs="?", const="custom,configs",
                      default="", help="Use matrix generator")
    pair.add_argument("--tcp-sources", default="custom,configs",
                      help="TCP sources: custom,configs,fake,faked,hostfake,fake_multi,fake_faked")
    pair.add_argument("--udp-sources", default="custom",
                      help="UDP sources: custom,configs")
    pair.add_argument("--scan-level", default="fast", choices=["single", "fast", "full"])
    pair.add_argument("--parallel", type=int, default=4)
    pair.add_argument("--max", type=int, default=100)
    pair.add_argument("--timeout", type=float, default=5.0)
    pair.add_argument("--udp-timeout", type=float, default=3.0)
    pair.add_argument("--tcp-only", action="store_true",
                      help="Skip UDP pair testing (TCP scan only)")
    pair.add_argument("-c", "--config", help="Single TCP .conf file")
    pair.add_argument("-u", "--udp-config", help="Single UDP .conf file")
    pair.add_argument("-C", "--configs-dir", default="configs")
    pair.add_argument("--ip", default="35.217.5.42")
    pair.add_argument("--port", type=int, default=50006)
    pair.add_argument("--auto-discover", action="store_true")
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
        # Alias to pair --tcp-only
        if args.generate:
            args.tcp_sources = args.generate if args.generate != "custom,configs" else args.tcp_sources or "custom,configs"
        args.generate = bool(args.generate)
        args.tcp_only = True
        args.full_voice = False
        args.udp_bypass = False
        args.auto_discover = False
        args.udp_sources = ""
        args.configs_dir = "configs"
        args.config = None
        args.udp_config = None
        if args.user_matrix:
            pass
        return asyncio.run(cmd_pair(args))
    elif args.command == "pair":
        # Forward custom --generate values to tcp_sources
        if args.generate and args.generate != "custom,configs":
            args.tcp_sources = args.generate
        args.generate = bool(args.generate) or bool(getattr(args, 'tcp_sources', '') != "custom,configs"
                                                     or getattr(args, 'udp_sources', '') != "custom")
        return asyncio.run(cmd_pair(args))
    else:
        parser.print_help()
        tcp_passed_local = sum(1 for r in tcp_results if r.success) if "tcp_results" in dir() else 0
        return 0 if tcp_passed_local > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
