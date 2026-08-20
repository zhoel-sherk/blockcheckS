"""Synchronous UDP voice strategy test."""

import asyncio

from blockchecks.checkers.voice_dns import (
    check_discover_mutex,
    discover_dns_alive,
    positive_discover_count,
    resolve_voice_targets,
)
from blockchecks.engine.config import DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
from blockchecks.engine.strategy_loader import StrategyLoader
from blockchecks.engine.test_runner import TestRunner
from blockchecks.terminal import CYAN, GREEN, RESET, YELLOW, error


def cmd_udp(args):
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
        error("specify --config or --configs-dir")
        return 1
    if not configs:
        error("no configs loaded")
        return 1

    voice_ip = args.ip
    voice_port = args.port
    explicit_ip = voice_ip != DEFAULT_VOICE_IP
    discover_dns = getattr(args, "discover_dns", None)
    auto_discover = getattr(args, "auto_discover", None)
    dns_count = positive_discover_count(discover_dns)
    auto_count = positive_discover_count(auto_discover)
    multi_eps: list = []

    if not explicit_ip and dns_count is not None:
        count = dns_count
        print(f"\n  {CYAN}DNS-alive discovering {count} voice endpoints...{RESET}")
        try:
            multi_eps = asyncio.run(
                discover_dns_alive(
                    count,
                    use_bootstrap=not getattr(args, "discover_dns_no_bootstrap", False),
                    region=getattr(args, "voice_region", None) or "finland",
                    try_burst=bool(getattr(args, "voice_burst", False)),
                )
            )
            if multi_eps:
                voice_ip, voice_port = multi_eps[0]["ip"], multi_eps[0]["port"]
                method = multi_eps[0].get("method", "?")
                boot = "on" if multi_eps[0].get("bootstrap") else "off"
                print(
                    f"  {GREEN}Voice source: dns-alive "
                    f"({len(multi_eps)}/{count}) {voice_ip}:{voice_port} "
                    f"method={method} bootstrap={boot} "
                    f"({multi_eps[0].get('hostname', '')}){RESET}"
                )
                for ep in multi_eps[1:3]:
                    print(f"  {GREEN}  + {ep['ip']}:{ep['port']} ({ep.get('hostname', '')}){RESET}")
                if len(multi_eps) > 3:
                    print(f"  {GREEN}  ... and {len(multi_eps) - 3} more{RESET}")
            else:
                print(f"  {YELLOW}No alive endpoints — using static DEFAULT_VOICE_*{RESET}")
                voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
        except Exception as e:
            print(f"  {YELLOW}discover-dns error: {e}{RESET}")
            voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
    elif not explicit_ip and auto_count is not None:
        count = auto_count
        print(f"\n  {CYAN}Auto-discovering {count} voice endpoints...{RESET}")
        try:
            from blockchecks.checkers.voice_discovery import discover_multiple

            multi_eps = asyncio.run(discover_multiple(count, use_dns=True))
            if multi_eps:
                voice_ip, voice_port = multi_eps[0]["ip"], multi_eps[0]["port"]
                print(
                    f"  {GREEN}Voice source: auto-discover "
                    f"({len(multi_eps)}) {voice_ip}:{voice_port}{RESET}"
                )
            else:
                print(f"  {YELLOW}No endpoints found — using static{RESET}")
                voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
        except Exception as e:
            print(f"  {YELLOW}Discovery error: {e}{RESET}")
            voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT

    targets = resolve_voice_targets(voice_ip, voice_port, multi_eps)
    print("\n  blockcheckS — UDP Voice test")
    print(f"  Targets: {len(targets)}  Items: {len(configs)}  Timeout: {args.timeout}s\n")
    runner = TestRunner(ns_name=args.ns)
    passed_any = 0
    total_time = 0.0
    for ip, port in targets:
        print(f"  {CYAN}--- ep={ip}:{port} ---{RESET}")
        report = runner.test_sequential_udp(
            configs, ip, port=port, timeout=args.timeout, qnum=args.qnum
        )
        passed_any += report.passed
        total_time += report.total_time_sec
        print(
            f"  Results @{ip}:{port}: "
            f"{report.passed}/{len(report.results)} passed ({report.total_time_sec:.1f}s)"
        )
    print(f"\n  Total passed probes: {passed_any} ({total_time:.1f}s)")
    return 0 if passed_any > 0 else 1
