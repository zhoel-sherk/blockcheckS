"""Async TCP×UDP pair matrix command."""

import asyncio
import glob
import os
import signal
import time

from colorama import Fore, Style

from blockchecks.checkers.dns_secure import prepare_dns_for_run
from blockchecks.cli.presets import list_presets
from blockchecks.engine.async_runner import AsyncTestRunner
from blockchecks.engine.config import (
    CONFIGS_DIR,
    DEFAULT_VOICE_IP,
    DEFAULT_VOICE_PORT,
    DPI_TESTER_SETTINGS,
    PROJECT_DIR,
    SECURE_DNS_DEFAULT,
    UNBLOCKED_DOM,
)
from blockchecks.engine.db_logger import StateDB, matrix_fingerprint
from blockchecks.engine.matrix_generator import MatrixGenerator, StrategyItem
from blockchecks.engine.preflight import PreflightOptions, run_preflight
from blockchecks.engine.strategy_loader import StrategyLoader

CYAN = Fore.CYAN
GREEN = Fore.GREEN + Style.BRIGHT
RED = Fore.RED + Style.BRIGHT
YELLOW = Fore.YELLOW
RESET = Style.RESET_ALL


async def cmd_pair(args):
    """TCP×UDP pair matrix with generator + async runner."""
    if getattr(args, "list_presets", False):
        list_presets()
        return 0

    db = StateDB(args.db)
    await db.init()

    preset_domains = []
    preset_name = getattr(args, "preset", None)
    if preset_name:
        preset_path = os.path.join(PROJECT_DIR, "presets", "domains", f"{preset_name}.txt")
        if os.path.exists(preset_path):
            with open(preset_path) as pf:
                preset_domains = [
                    line.strip() for line in pf if line.strip() and not line.startswith("#")
                ]
            print(f"  {Fore.CYAN}Preset '{preset_name}': {len(preset_domains)} domains{RESET}")
        else:
            print(f"  {Fore.YELLOW}Preset '{preset_name}' not found. Available:{RESET}")
            for f in sorted(glob.glob(os.path.join(PROJECT_DIR, "presets/domains", "*.txt"))):
                print(f"    {os.path.basename(f).replace('.txt', '')}")
            return 1

    if not args.domain and not preset_domains:
        print(f"{Fore.RED}ERROR: --domain or --preset required{RESET}")
        return 1
    if not args.domain and preset_domains:
        args.domain = preset_domains[0]

    pool_size = args.parallel or 4

    domains_for_dns = list(
        dict.fromkeys((preset_domains or []) + ([args.domain] if args.domain else []))
    )
    secure_dns = SECURE_DNS_DEFAULT and not getattr(args, "no_secure_dns", False)
    dns_cache, dns_audits, dns_rc = prepare_dns_for_run(
        domains_for_dns,
        secure_dns=secure_dns,
        skip_audit=getattr(args, "skip_dns_audit", False),
        allow_hijack=getattr(args, "allow_dns_hijack", False),
        doh_server=getattr(args, "doh_server", None) or None,
    )
    if dns_rc:
        return dns_rc

    test_domains = list(
        dict.fromkeys((preset_domains or []) + ([args.domain] if args.domain else []))
    )
    preflight = run_preflight(
        test_domains,
        PreflightOptions(
            unblocked_dom=getattr(args, "unblocked_dom", None) or UNBLOCKED_DOM,
            timeout=min(getattr(args, "timeout", 5.0), 8.0),
            skip_baseline=getattr(args, "skip_baseline", False),
            skip_port_block=getattr(args, "skip_port_block", False),
            skip_prolog=getattr(args, "skip_prolog", False),
            skip_ip_block=getattr(args, "skip_ip_block", False),
            skip_nfqws2_check=getattr(args, "skip_nfqws2_check", False),
            abort_on_nfqws2=getattr(args, "abort_on_nfqws2", False),
            force=getattr(args, "force", False),
            dns_cache=dns_cache,
        ),
    )
    if preflight.exit_code:
        print(f"{Fore.RED}ERROR: preflight failed: {preflight.error}{RESET}")
        return preflight.exit_code
    if args.domain and args.domain in preflight.skip_domains and not getattr(args, "force", False):
        print(f"{YELLOW}Prolog: {args.domain} works without bypass — nothing to test{RESET}")
        print(f"{YELLOW}Use --force to run strategy matrix anyway{RESET}")
        return 0

    runner = AsyncTestRunner(
        pool_size=pool_size,
        db=db,
        disable_ech=bool(getattr(args, "disable_ech", False)),
        secure_dns=secure_dns,
        dns_cache=dns_cache,
        dns_audit={r.domain: r for r in dns_audits},
        repeats=max(1, getattr(args, "repeats", 1) or 1),
        parallel_repeats=bool(getattr(args, "parallel_repeats", False)),
        try_wssize=getattr(args, "protocol", "tls12") == "tls12",
    )
    stop_event = asyncio.Event()

    loop = asyncio.get_running_loop()

    def _request_stop():
        stop_event.set()

    try:
        loop.add_signal_handler(signal.SIGINT, _request_stop)
        loop.add_signal_handler(signal.SIGTERM, _request_stop)
    except (NotImplementedError, RuntimeError):
        signal.signal(signal.SIGINT, lambda *a: _request_stop())
        signal.signal(signal.SIGTERM, lambda *a: _request_stop())

    try:
        await runner.start()

        voice_ip = getattr(args, "ip", None) or DEFAULT_VOICE_IP
        voice_port = getattr(args, "port", None) or DEFAULT_VOICE_PORT

        from blockchecks.checkers.voice_discovery import load_token
        from blockchecks.checkers.voice_dns import check_discover_mutex, discover_dns_alive

        mutex_err = check_discover_mutex(
            getattr(args, "discover_dns", None),
            getattr(args, "auto_discover", None),
        )
        if mutex_err:
            print(f"{Fore.RED}{mutex_err}{RESET}")
            return 1

        token = load_token()
        has_token = bool(token)
        full_voice = args.full_voice and has_token

        explicit_ip = voice_ip != DEFAULT_VOICE_IP
        discover_dns = getattr(args, "discover_dns", None)
        auto_discover = getattr(args, "auto_discover", None)
        multi_eps = []

        if not explicit_ip and discover_dns is not None and int(discover_dns) > 0:
            count = int(discover_dns)
            print(
                f"\n  {CYAN}DNS-alive discovering {count} voice endpoints "
                f"(DNS + Maks-gaming + STUN)...{RESET}"
            )
            try:
                multi_eps = await discover_dns_alive(
                    count,
                    use_bootstrap=not getattr(args, "discover_dns_no_bootstrap", False),
                )
                if multi_eps:
                    for ep in multi_eps[:3]:
                        src = ep.get("source", "dns-alive")
                        ms = ep.get("stun_ms", "?")
                        method = ep.get("method", "?")
                        print(
                            f"  {GREEN}  {ep['ip']}:{ep['port']} "
                            f"({ep.get('hostname', '')}) "
                            f"[{src} {method} {ms}ms]{RESET}"
                        )
                    if len(multi_eps) > 3:
                        print(f"  {GREEN}  ... and {len(multi_eps) - 3} more{RESET}")
                    voice_ip = multi_eps[0]["ip"]
                    voice_port = multi_eps[0]["port"]
                    boot = "on" if multi_eps[0].get("bootstrap") else "off"
                    print(
                        f"  {GREEN}Voice source: dns-alive "
                        f"({len(multi_eps)}/{count}) {voice_ip}:{voice_port} "
                        f"method={multi_eps[0].get('method', '?')} "
                        f"bootstrap={boot}{RESET}"
                    )
                else:
                    print(
                        f"  {YELLOW}No alive endpoints — using static DEFAULT_VOICE_* "
                        f"(try --auto-discover / VPN if needed){RESET}"
                    )
                    voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
            except Exception as e:
                print(f"  {YELLOW}discover-dns error: {e}{RESET}")
                voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
        elif not explicit_ip and auto_discover is not None and int(auto_discover) > 0:
            count = int(auto_discover)
            print(f"\n  {CYAN}Auto-discovering {count} voice endpoints...{RESET}")
            try:
                from blockchecks.checkers.voice_discovery import discover_multiple

                multi_eps = await discover_multiple(count, use_dns=True)
                if multi_eps:
                    for ep in multi_eps[:3]:
                        print(f"  {GREEN}  {ep['ip']}:{ep['port']} ({ep['hostname']}){RESET}")
                    if len(multi_eps) > 3:
                        print(f"  {GREEN}  ... and {len(multi_eps) - 3} more{RESET}")
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
            print(
                f"  {CYAN}Full-voice mode: discovery+STUN (gateway WS probe not implemented){RESET}"
            )

        strategy_preset = getattr(args, "strategy_preset", None)
        if strategy_preset:
            name = strategy_preset
            for suffix in (".tls", ".txt"):
                if name.endswith(suffix):
                    name = name[: -len(suffix)]
                    break
            found = False
            for ext in [".tls", ".txt"]:
                sp = os.path.join(PROJECT_DIR, "presets", "strategies", f"{name}{ext}")
                if os.path.exists(sp):
                    args.user_matrix = sp
                    found = True
                    break
            if not found:
                print(f"  {Fore.RED}ERROR: strategy preset '{strategy_preset}' not found{RESET}")
                return 1

        do_generate = getattr(args, "generate", False)
        user_matrix = getattr(args, "user_matrix", "") or ""
        run_set: set = set()
        tcp_items = []
        udp_items = []

        if getattr(args, "config", None):
            tcp_items = [
                StrategyItem(
                    label=os.path.basename(args.config).replace(".conf", ""),
                    strategy=args.config,
                    is_config=True,
                )
            ]
            do_generate = False
        if getattr(args, "udp_config", None):
            udp_items = [
                StrategyItem(
                    label=os.path.basename(args.udp_config).replace(".conf", ""),
                    strategy=args.udp_config,
                    is_config=True,
                )
            ]

        protocol = getattr(args, "protocol", "tls12") or "tls12"

        if do_generate or user_matrix:
            scanner = MatrixGenerator()
            tcp_src = getattr(args, "tcp_sources", "") or "custom,configs"
            udp_src = getattr(args, "udp_sources", "") or "custom"
            if getattr(args, "tcp_only", False):
                udp_src = ""
            tcp_sources = [s for s in tcp_src.split(",") if s]
            udp_sources = [s for s in udp_src.split(",") if s]

            print(f"\n  {CYAN}Generating strategies...{RESET}")
            if not tcp_items:
                tcp_items = await scanner.generate_tcp(
                    sources=tcp_sources or ["custom", "configs"],
                    domain=args.domain,
                    scan_level=getattr(args, "scan_level", "fast"),
                    max_count=getattr(args, "max", 100),
                    state_db=db,
                    user_matrix=user_matrix,
                    run_set=run_set,
                    protocol=protocol,
                )
            if not udp_items and udp_sources and not args.tcp_only:
                udp_items = await scanner.generate_udp(
                    sources=udp_sources,
                    domain=args.domain,
                    scan_level=args.scan_level,
                    max_count=max(1, args.max // 2) if args.max >= 2 else 50,
                    state_db=db,
                    user_matrix=user_matrix,
                )
            print(f"  Generated: {len(tcp_items)} TCP + {len(udp_items)} UDP strategies")
        elif not tcp_items:
            loader = StrategyLoader()
            tcp_configs = loader.from_config_dir(args.configs_dir or CONFIGS_DIR)
            tcp_items = [
                StrategyItem(
                    label=os.path.basename(c).replace(".conf", ""), strategy=c, is_config=True
                )
                for c in tcp_configs
                if "udp_voice" not in c.lower()
            ]
            if not udp_items:
                udp_items = [
                    StrategyItem(
                        label=os.path.basename(c).replace(".conf", ""), strategy=c, is_config=True
                    )
                    for c in tcp_configs
                    if "udp_voice" in c.lower()
                ]

        domains_to_test = preset_domains if preset_domains else [args.domain]

        print(
            f"\n  {CYAN}blockcheckS — {'Pair Matrix' if not args.tcp_only else 'TCP Scan'}{RESET}"
        )
        print(
            f"  Domain:     {', '.join(domains_to_test[:5])}"
            f"{'...' if len(domains_to_test) > 5 else ''}"
        )
        print(f"  TCP:        {len(tcp_items)} strategies")
        print(f"  UDP:        {len(udp_items)} strategies")
        print(f"  Voice:      {voice_ip}:{voice_port}")
        if not tcp_items:
            print("  ERROR: no strategies loaded")
            return 1
        print(f"  Full Voice: {'discovery+STUN' if full_voice else 'STUN only'}")
        print(f"  UDP Bypass: {'yes' if args.udp_bypass else 'no'}")
        print(f"  Workers:    {pool_size}")
        print(f"  DB:         {args.db}")

        fp = matrix_fingerprint(
            [i.strategy for i in tcp_items],
            [i.strategy for i in udp_items],
            getattr(args, "scan_level", "fast"),
            getattr(args, "max", 100),
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
                print(
                    f"  {YELLOW}Resuming after "
                    f"{resume_from.tcp_label}+{resume_from.udp_label}{RESET}"
                )
            else:
                print(f"  {YELLOW}No checkpoint found — starting fresh{RESET}")

        if stop_event.is_set():
            return 130

        t0 = time.perf_counter()
        all_tcp_results = []
        pairs = []
        tcp_passed = 0

        for domain in domains_to_test:
            if stop_event.is_set():
                return 130
            print(f"\n  {CYAN}[TCP Phase]{RESET} {domain}: {len(tcp_items)} strategies...")
            tcp_results = await runner.test_batch_tcp(tcp_items, domain, args.timeout)
            all_tcp_results.extend(tcp_results)
            domain_passed = sum(1 for r in tcp_results if r.success)
            tcp_passed += domain_passed
            print(f"\n  TCP {domain}: {GREEN}{domain_passed}{RESET}/{len(tcp_results)} passed")

            for r in tcp_results:
                if r.success:
                    run_set.add(r.item.label)

            if not args.tcp_only and udp_items and domain == domains_to_test[0]:
                if stop_event.is_set():
                    return 130
                print(f"\n  {CYAN}[UDP Pairs]{RESET} {len(udp_items)} strategies...")
                pairs = await runner.test_pair_matrix(
                    tcp_results,
                    udp_items,
                    domain,
                    voice_ip,
                    voice_port,
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
