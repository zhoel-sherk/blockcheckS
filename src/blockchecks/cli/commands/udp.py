"""Synchronous UDP voice strategy test command."""

import asyncio

from colorama import Fore, Style

from blockchecks.engine.config import DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
from blockchecks.engine.strategy_loader import StrategyLoader
from blockchecks.engine.test_runner import TestRunner

CYAN = Fore.CYAN
GREEN = Fore.GREEN + Style.BRIGHT
YELLOW = Fore.YELLOW
RESET = Style.RESET_ALL


def cmd_udp(args):
    from blockchecks.checkers.voice_dns import check_discover_mutex, discover_dns_alive

    mutex_err = check_discover_mutex(
        getattr(args, "discover_dns", None),
        getattr(args, "auto_discover", None),
    )
    if mutex_err:
        print(mutex_err)
        return 1

    loader = StrategyLoader()
    if args.config:
        configs = loader.from_config(args.config)
    elif args.configs_dir:
        configs = loader.from_config_dir(args.configs_dir)
    else:
        print("ERROR: specify --config or --configs-dir")
        return 1
    if not configs:
        print("ERROR: no configs loaded")
        return 1

    voice_ip = args.ip
    voice_port = args.port
    explicit_ip = voice_ip != DEFAULT_VOICE_IP
    discover_dns = getattr(args, "discover_dns", None)
    auto_discover = getattr(args, "auto_discover", None)

    if not explicit_ip and discover_dns is not None and int(discover_dns) > 0:
        count = int(discover_dns)
        print(f"\n  {CYAN}DNS-alive discovering {count} voice endpoints...{RESET}")
        try:
            eps = asyncio.run(
                discover_dns_alive(
                    count,
                    use_bootstrap=not getattr(args, "discover_dns_no_bootstrap", False),
                )
            )
            if eps:
                voice_ip, voice_port = eps[0]["ip"], eps[0]["port"]
                method = eps[0].get("method", "?")
                boot = "on" if eps[0].get("bootstrap") else "off"
                print(
                    f"  {GREEN}Voice source: dns-alive "
                    f"({len(eps)}/{count}) {voice_ip}:{voice_port} "
                    f"method={method} bootstrap={boot} "
                    f"({eps[0].get('hostname', '')}){RESET}"
                )
            else:
                print(f"  {YELLOW}No alive endpoints — using static DEFAULT_VOICE_*{RESET}")
                voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
        except Exception as e:
            print(f"  {YELLOW}discover-dns error: {e}{RESET}")
            voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
    elif not explicit_ip and auto_discover is not None and int(auto_discover) > 0:
        count = int(auto_discover)
        print(f"\n  {CYAN}Auto-discovering {count} voice endpoints...{RESET}")
        try:
            from blockchecks.checkers.voice_discovery import discover_multiple

            multi_eps = asyncio.run(discover_multiple(count, use_dns=True))
            if multi_eps:
                voice_ip, voice_port = multi_eps[0]["ip"], multi_eps[0]["port"]
                print(f"  {GREEN}Voice source: auto-discover {voice_ip}:{voice_port}{RESET}")
            else:
                print(f"  {YELLOW}No endpoints found — using static{RESET}")
                voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
        except Exception as e:
            print(f"  {YELLOW}Discovery error: {e}{RESET}")
            voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT

    print("\n  blockcheckS — UDP Voice test")
    print(f"  Target: {voice_ip}:{voice_port}  Items: {len(configs)}  Timeout: {args.timeout}s\n")
    runner = TestRunner(ns_name=args.ns)
    report = runner.test_sequential_udp(
        configs, voice_ip, port=voice_port, timeout=args.timeout, qnum=args.qnum
    )
    print(
        f"\n  Results: {report.passed}/{len(report.results)} passed ({report.total_time_sec:.1f}s)"
    )
    return 0 if report.passed > 0 else 1
