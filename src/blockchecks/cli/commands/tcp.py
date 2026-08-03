"""Synchronous TCP strategy test command."""

import asyncio

from colorama import Fore, Style

from blockchecks.checkers.curl_probe import repeats_from_args
from blockchecks.checkers.dns_secure import prepare_dns_for_run
from blockchecks.engine.config import CONFIGS_DIR, SECURE_DNS_DEFAULT
from blockchecks.engine.run_deadline import RunDeadline, parse_time_limit_seconds
from blockchecks.engine.strategy_loader import StrategyLoader
from blockchecks.engine.test_runner import TestRunner

GREEN = Fore.GREEN + Style.BRIGHT
RESET = Style.RESET_ALL


def cmd_tcp(args):
    try:
        budget_sec = parse_time_limit_seconds(args)
    except ValueError as e:
        print(f"ERROR: {e}")
        return 1

    loader = StrategyLoader()
    source_loaders = (
        ("config", lambda: (loader.from_config(args.config), "config") if args.config else None),
        (
            "configs_dir",
            lambda: (loader.from_config_dir(args.configs_dir), CONFIGS_DIR)
            if args.configs_dir
            else None,
        ),
        ("file", lambda: (loader.from_file(args.file), "string") if args.file else None),
        (
            "strategy",
            lambda: (loader.from_string(args.strategy), "string") if args.strategy else None,
        ),
        (
            "custom",
            lambda: (loader.from_custom_dir(args.test_dir, args.protocol), "string")
            if args.test == "custom"
            else None,
        ),
    )
    loaded = None
    for _, fn in source_loaders:
        loaded = fn()
        if loaded is not None:
            break
    if loaded is None:
        print("ERROR: specify --strategy, --config, --configs-dir, --file, or --test")
        return 1
    strategies, mode = loaded
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

    deadline = None
    if budget_sec is not None:
        deadline = RunDeadline(asyncio.Event(), budget_sec=budget_sec)
        deadline.arm()
        print(f"  Time limit: {deadline.budget_label()}")

    repeats, parallel_repeats, repeats_mode, quick_break = repeats_from_args(args)

    runner = TestRunner(
        ns_name=args.ns,
        dns_cache=dns_cache,
        secure_dns=secure_dns,
        repeats=repeats,
        parallel_repeats=parallel_repeats,
        repeats_mode=repeats_mode,
        quick_break=quick_break,
    )
    total = len(strategies)
    if mode in (CONFIGS_DIR, "config") and strategies:
        report = runner.test_sequential_configs(
            strategies, args.domain, timeout=args.timeout, qnum=args.qnum, deadline=deadline
        )
    else:
        report = runner.test_sequential(
            strategies,
            args.domain,
            timeout=args.timeout,
            hostlist=[args.domain] if not args.no_hostlist else None,
            qnum=args.qnum,
            deadline=deadline,
        )
    print(
        f"\n  Results: {report.passed}/{len(report.results)} passed ({report.total_time_sec:.1f}s)"
    )
    if report.stopped_reason == "time_limit" and deadline:
        print(
            f"  Stopped: time limit ({deadline.budget_label()}) "
            f"after {len(report.results)}/{total} strategies"
        )
    return 0 if report.passed > 0 else 1
