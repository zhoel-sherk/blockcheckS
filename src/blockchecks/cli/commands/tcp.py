"""Synchronous TCP strategy test command."""

from colorama import Fore, Style

from blockchecks.checkers.dns_secure import prepare_dns_for_run
from blockchecks.engine.config import CONFIGS_DIR, SECURE_DNS_DEFAULT
from blockchecks.engine.strategy_loader import StrategyLoader
from blockchecks.engine.test_runner import TestRunner

GREEN = Fore.GREEN + Style.BRIGHT
RESET = Style.RESET_ALL


def cmd_tcp(args):
    loader = StrategyLoader()
    mode = None
    if args.config:
        strategies = loader.from_config(args.config)
        mode = "config"
    elif args.configs_dir:
        strategies = loader.from_config_dir(args.configs_dir)
        mode = CONFIGS_DIR
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
    print("\n  blockcheckS — TCP TLS test")
    print(f"  Domain: {args.domain}  Items: {len(strategies)}  Timeout: {args.timeout}s\n")
    secure_dns = SECURE_DNS_DEFAULT and not getattr(args, "no_secure_dns", False)
    dns_cache, _, dns_rc = prepare_dns_for_run(
        [args.domain],
        secure_dns=secure_dns,
        skip_audit=getattr(args, "skip_dns_audit", False),
        allow_hijack=getattr(args, "allow_dns_hijack", False),
        doh_server=getattr(args, "doh_server", None) or None,
    )
    if dns_rc:
        return dns_rc
    runner = TestRunner(ns_name=args.ns, dns_cache=dns_cache, secure_dns=secure_dns)
    if mode in (CONFIGS_DIR, "config") and strategies:
        report = runner.test_sequential_configs(
            strategies, args.domain, timeout=args.timeout, qnum=args.qnum
        )
    else:
        report = runner.test_sequential(
            strategies,
            args.domain,
            timeout=args.timeout,
            hostlist=[args.domain] if not args.no_hostlist else None,
            qnum=args.qnum,
        )
    print(
        f"\n  Results: {report.passed}/{len(report.results)} passed ({report.total_time_sec:.1f}s)"
    )
    return 0 if report.passed > 0 else 1
