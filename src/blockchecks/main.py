"""bs full — mass strategy×coverage orchestrator + conf export."""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
import time

from colorama import Fore, Style
from colorama import init as colorama_init

from blockchecks.checkers.dns_secure import prepare_dns_for_run
from blockchecks.checkers.http3 import supports_http3
from blockchecks.cli.parser import (
    add_curl_repeats_args,
    add_family_gate_args,
    add_protocol_phase_args,
)
from blockchecks.engine.async_runner import AsyncTestRunner
from blockchecks.engine.config import (
    DEFAULT_CURL_PARALLEL,
    DEFAULT_VOICE_IP,
    DEFAULT_VOICE_PORT,
    MAX_CURL_PARALLEL,
    SECURE_DNS_DEFAULT,
    UNBLOCKED_DOM,
)
from blockchecks.engine.db_logger import StateDB, matrix_fingerprint
from blockchecks.engine.domain_loader import (
    DEFAULT_DOMAINS_FILE,
    format_skip_summary,
    load_domains,
    warn_zero_pass_domains,
)
from blockchecks.engine.family_needs import run_tcp_with_family_gates
from blockchecks.engine.matrix_generator import MatrixGenerator, StrategyItem
from blockchecks.engine.preflight import PreflightOptions, run_preflight
from blockchecks.engine.settle_profile import auto_load_profile, load_profile
from blockchecks.engine.tcp_fanout import fanout_allowed, fanout_batches
from blockchecks.nfconf import export_configs

colorama_init(autoreset=True)
CYAN = Fore.CYAN
GREEN = Fore.GREEN + Style.BRIGHT
YELLOW = Fore.YELLOW
RED = Fore.RED + Style.BRIGHT
RESET = Style.RESET_ALL


def _cap(n: int) -> int:
    """0 / negative → uncapped sentinel for MatrixGenerator slicing."""
    return 999_999 if n <= 0 else n


def _apply_gp_protocol_flags(args) -> bool:
    """A10: GP ENABLE_* mirror — returns True to skip TCP TLS phase."""
    if getattr(args, "http_off", False):
        args.no_http = True
    if getattr(args, "http3_off", False):
        args.no_quic = True
    skip_tcp = False
    if getattr(args, "tls12_off", False) and args.protocol == "tls12":
        skip_tcp = True
    if getattr(args, "tls13_off", False) and args.protocol == "tls13":
        skip_tcp = True
    return skip_tcp


async def run_full(args) -> int:
    db = StateDB(args.db)
    await db.init()

    domains_file = args.domains_file or DEFAULT_DOMAINS_FILE
    try:
        loaded = load_domains(
            domains_file,
            allow_unsafe=getattr(args, "allow_unsafe_domains", False),
        )
    except FileNotFoundError:
        print(f"{RED}ERROR: domains file not found: {domains_file}{RESET}")
        return 1
    domains = loaded.domains
    if not domains:
        print(
            f"{RED}ERROR: no domains left after denylist filter "
            f"(use --allow-unsafe-domains){RESET}"
        )
        return 1
    if loaded.skipped:
        print(f"  {YELLOW}{format_skip_summary(loaded.skipped)}{RESET}")

    secure_dns = SECURE_DNS_DEFAULT and not getattr(args, "no_secure_dns", False)
    dns_cache, dns_audits, dns_rc = prepare_dns_for_run(
        domains,
        secure_dns=secure_dns,
        skip_audit=getattr(args, "skip_dns_audit", False),
        allow_hijack=getattr(args, "allow_dns_hijack", False),
        doh_server=getattr(args, "doh_server", None) or None,
    )
    if dns_rc:
        return dns_rc

    skip_tcp_tls = _apply_gp_protocol_flags(args)

    primary = args.domain or domains[0]

    preflight = run_preflight(
        domains,
        PreflightOptions(
            unblocked_dom=getattr(args, "unblocked_dom", None) or UNBLOCKED_DOM,
            timeout=min(args.timeout, 8.0),
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
        print(f"{RED}ERROR: preflight failed: {preflight.error}{RESET}")
        return preflight.exit_code

    if preflight.skip_domains:
        skipped = sorted(preflight.skip_domains)
        print(f"  {YELLOW}Prolog skip: {', '.join(skipped)}{RESET}")
        domains = [d for d in domains if d not in preflight.skip_domains]
        if not domains:
            print(f"{YELLOW}All domains work without bypass — nothing to test{RESET}")
            return 0
        if primary in preflight.skip_domains:
            primary = domains[0]

    tcp_sources = [s for s in args.tcp_sources.split(",") if s]
    udp_sources = [s for s in args.udp_sources.split(",") if s]
    quic_sources = [s for s in args.quic_sources.split(",") if s]
    http_sources = [s for s in getattr(args, "http_sources", "custom,standard_http").split(",") if s]

    max_n = _cap(args.max)
    scan_level = args.scan_level
    parallel = args.parallel
    steps = 7 if not getattr(args, "no_http", False) else 6

    print(f"\n  {CYAN}blockcheckS — FULL run{RESET}")
    print(f"  Domains:    {len(domains)} from {domains_file}")
    print(f"  Primary:    {primary}")
    print(f"  TCP src:    {tcp_sources}  level={scan_level}  max={args.max or 'uncapped'}")
    if not getattr(args, "no_http", False):
        print(f"  HTTP src:   {http_sources}")
    print(f"  UDP src:    {udp_sources}")
    print(f"  QUIC src:   {quic_sources}")
    print(f"  Parallel:   {parallel}  resume={bool(args.resume)}")
    if not getattr(args, "no_quic", False) and not args.tcp_only:
        if supports_http3():
            print(f"  HTTP/3:     {GREEN}curl v3only supported{RESET}")
        else:
            print(f"  {YELLOW}HTTP/3: curl lacks --http3-only — QUIC phase will fail{RESET}")
    print(f"  DB:         {args.db}")

    gen = MatrixGenerator()
    print(f"\n  {CYAN}[1/{steps}] Generating strategies...{RESET}")
    tcp_items: list[StrategyItem] = []
    if not skip_tcp_tls:
        tcp_items = await gen.generate_tcp(
            sources=tcp_sources,
            domain=primary,
            scan_level=scan_level,
            max_count=max_n,
            state_db=db,
            protocol=args.protocol,
        )
    udp_items: list[StrategyItem] = []
    if not args.tcp_only:
        udp_items = await gen.generate_udp(
            sources=udp_sources,
            domain=primary,
            scan_level=scan_level,
            max_count=max(50, max_n // 20),
            state_db=db,
        )
    quic_items: list[StrategyItem] = []
    if not args.no_quic and not args.tcp_only:
        quic_items = await gen.generate_quic(
            sources=quic_sources,
            domain=primary,
            scan_level=scan_level,
            max_count=max(30, max_n // 50) if max_n else 50,
            state_db=db,
        )

    http_items: list[StrategyItem] = []
    if not getattr(args, "no_http", False):
        http_items = await gen.generate_http(
            sources=http_sources,
            domain=primary,
            scan_level=scan_level,
            max_count=max(30, max_n // 20) if max_n else 50,
            state_db=db,
        )

    print(
        f"  TCP={len(tcp_items)}  HTTP={len(http_items)}  "
        f"UDP={len(udp_items)}  QUIC={len(quic_items)}"
    )
    if skip_tcp_tls:
        print(f"  {YELLOW}TCP TLS phase skipped (--tls{args.protocol.replace('tls', '')}-off){RESET}")
    elif not tcp_items:
        print(f"{RED}ERROR: no TCP strategies generated{RESET}")
        return 1

    total_tcp_jobs = len(tcp_items) * len(domains) if tcp_items else 0
    if total_tcp_jobs:
        eta_sec = total_tcp_jobs * 3.0 / max(parallel, 1)
        print(f"  TCP jobs:   {total_tcp_jobs}  (~ETA {eta_sec / 3600:.1f}h @ ~3s/job)")

    use_family_gates = (
        scan_level != "full"
        and not getattr(args, "no_family_gates", False)
        and any(s in ("standard", "fake", "hostfake", "faked", "fake_multi", "fake_faked") for s in tcp_sources)
    )
    curl_parallel = max(1, min(getattr(args, "curl_parallel", DEFAULT_CURL_PARALLEL), MAX_CURL_PARALLEL))
    fanout_ok, fanout_note = fanout_allowed(
        curl_parallel=curl_parallel,
        use_family_gates=use_family_gates,
        domains=domains,
        protocol=args.protocol,
    )
    use_fanout = fanout_ok and curl_parallel > 1
    if curl_parallel > 1 and not fanout_ok and fanout_note.startswith("family"):
        print(f"  {YELLOW}curl-parallel disabled: {fanout_note}{RESET}")
        curl_parallel = 1
    elif use_fanout:
        print(f"  {GREEN}curl-parallel: {curl_parallel}{RESET} (B2 fan-out)")
        if fanout_note:
            print(f"  {YELLOW}{fanout_note}{RESET}")
    if use_family_gates:
        print(f"  Family gates: {GREEN}on{RESET} (BC2-6 need_* chain)")

    settle_profile = None
    if getattr(args, "no_settle_profile", False):
        settle_profile = None
    elif getattr(args, "settle_profile", None):
        settle_profile = load_profile(args.settle_profile)
    else:
        settle_profile = auto_load_profile()
    if settle_profile and settle_profile.source_path:
        d = settle_profile.defaults
        hint = (
            f"settle={d.settle_max}s curl={d.curl_timeout}s"
            if d
            else f"{len(settle_profile.strategies)} strategies"
        )
        print(f"  {GREEN}Settle profile:{RESET} {settle_profile.source_path} ({hint})")

    fp = matrix_fingerprint(
        [i.strategy for i in tcp_items],
        [i.strategy for i in udp_items],
        scan_level=scan_level,
        max_count=args.max,
    )
    print(f"  Fingerprint:{fp}")

    runner = AsyncTestRunner(
        pool_size=parallel,
        db=db,
        secure_dns=secure_dns,
        dns_cache=dns_cache,
        dns_audit={r.domain: r for r in dns_audits},
        repeats=max(1, getattr(args, "repeats", 1) or 1),
        parallel_repeats=bool(getattr(args, "parallel_repeats", False)),
        try_wssize=getattr(args, "protocol", "tls12") == "tls12",
        settle_profile=settle_profile,
    )
    stop = asyncio.Event()

    def _stop(*_a):
        stop.set()

    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, _stop)
        loop.add_signal_handler(signal.SIGTERM, _stop)
    except (NotImplementedError, RuntimeError):
        signal.signal(signal.SIGINT, lambda *_: _stop())

    await runner.start()
    try:
        # ── TCP × coverage ──
        if tcp_items:
            print(f"\n  {CYAN}[2/{steps}] TCP × coverage ({len(domains)} domains)...{RESET}")
            done = 0
            skipped = 0
            passed = 0
            t0 = time.perf_counter()

            def _progress(d: int, s: int, p: int):
                nonlocal done, skipped, passed
                done, skipped, passed = d, s, p
                if done % 50 == 0 or done == total_tcp_jobs:
                    elapsed = time.perf_counter() - t0
                    rate = done / elapsed if elapsed > 0 else 0
                    left = (total_tcp_jobs - done) / rate if rate > 0 else 0
                    print(
                        f"  [{done}/{total_tcp_jobs}] pass={passed} skip={skipped} "
                        f"{rate:.2f}/s ETA {left / 60:.0f}m"
                    )

            if use_family_gates:

                async def _run_domain(domain: str):
                    nonlocal done, skipped, passed
                    if stop.is_set():
                        return

                    async def _resume(label: str, dom: str) -> bool:
                        return bool(args.resume and await db.has_tcp_result(label, dom))

                    _, d_done, d_skip, d_pass = await run_tcp_with_family_gates(
                        runner,
                        tcp_items,
                        domain,
                        scan_level=scan_level,
                        timeout=args.timeout,
                        stop_event=stop,
                        resume_check=_resume if args.resume else None,
                    )
                    done += d_done
                    skipped += d_skip
                    passed += d_pass
                    _progress(done, skipped, passed)

                for domain in domains:
                    if stop.is_set():
                        print(f"  {YELLOW}Stopped by signal{RESET}")
                        break
                    await _run_domain(domain)
            elif use_fanout:

                async def _one_strategy(item: StrategyItem):
                    nonlocal done, skipped, passed
                    if stop.is_set():
                        return
                    pending = [
                        d
                        for d in domains
                        if not (args.resume and await db.has_tcp_result(item.label, d))
                    ]
                    skipped += len(domains) - len(pending)
                    done += len(domains) - len(pending)
                    if not pending:
                        return
                    batches = fanout_batches(
                        pending,
                        protocol=args.protocol,
                        curl_parallel=curl_parallel,
                    )
                    for batch in batches:
                        if stop.is_set():
                            return
                        batch_results = await runner.test_tcp_domains(
                            item, batch, timeout=args.timeout, curl_parallel=len(batch)
                        )
                        for r in batch_results:
                            done += 1
                            if r.success:
                                passed += 1
                        _progress(done, skipped, passed)

                tasks = [_one_strategy(item) for item in tcp_items]
                chunk = max(1, parallel)
                for i in range(0, len(tasks), chunk):
                    if stop.is_set():
                        print(f"  {YELLOW}Stopped by signal{RESET}")
                        break
                    await asyncio.gather(*tasks[i : i + chunk])
            else:

                async def _one(item: StrategyItem, domain: str):
                    nonlocal done, skipped, passed
                    if stop.is_set():
                        return
                    if args.resume and await db.has_tcp_result(item.label, domain):
                        skipped += 1
                        done += 1
                        return
                    r = await runner.test_tcp(item, domain, timeout=args.timeout)
                    done += 1
                    if r.success:
                        passed += 1
                    _progress(done, skipped, passed)

                tasks = [_one(item, domain) for item in tcp_items for domain in domains]
                chunk = 200
                for i in range(0, len(tasks), chunk):
                    if stop.is_set():
                        print(f"  {YELLOW}Stopped by signal{RESET}")
                        break
                    await asyncio.gather(*tasks[i : i + chunk])

            print(
                f"  {GREEN}TCP done: {passed} PASS, {skipped} skipped, "
                f"{done - skipped - passed} FAIL/other{RESET}"
            )
            zero_warn = getattr(args, "zero_pass_warn", 10)
            if zero_warn > 0:
                zero_domains = await warn_zero_pass_domains(
                    db, domains, min_results=zero_warn, protos=("tcp",)
                )
                if zero_domains:
                    print(
                        f"  {YELLOW}WARN: 0% PASS after {zero_warn}+ runs: "
                        f"{', '.join(zero_domains)}{RESET}"
                    )
        else:
            print(f"\n  {CYAN}[2/{steps}] TCP × coverage skipped{RESET}")

        # ── HTTP :80 ──
        if http_items and not getattr(args, "no_http", False):
            print(f"\n  {CYAN}[3/{steps}] HTTP :80 ({len(http_items)} strategies)...{RESET}")
            http_done = http_passed = http_skipped = 0

            async def _one_http(item: StrategyItem, domain: str):
                nonlocal http_done, http_skipped, http_passed
                if stop.is_set():
                    return
                if args.resume and await db.has_tcp_result(item.label, domain, proto="http"):
                    http_skipped += 1
                    http_done += 1
                    return
                r = await runner.test_tcp(item, domain, timeout=args.timeout)
                http_done += 1
                if r.success:
                    http_passed += 1

            http_tasks = [_one_http(item, d) for item in http_items for d in domains]
            for i in range(0, len(http_tasks), 200):
                if stop.is_set():
                    break
                await asyncio.gather(*http_tasks[i : i + 200])
            print(
                f"  {GREEN}HTTP done: {http_passed} PASS, {http_skipped} skipped, "
                f"{http_done - http_skipped - http_passed} FAIL/other{RESET}"
            )
        elif not getattr(args, "no_http", False):
            print(f"\n  {CYAN}[3/{steps}] HTTP skipped (no strategies){RESET}")

        voice_step = 4 if steps == 7 else 3
        quic_step = 5 if steps == 7 else 4
        pair_step = 6 if steps == 7 else 5
        export_step = 7 if steps == 7 else 6

        voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
        if not args.tcp_only and not args.no_voice:
            print(f"\n  {CYAN}[{voice_step}/{steps}] Voice discover-dns...{RESET}")
            try:
                from blockchecks.checkers.voice_dns import discover_dns_alive

                eps = await discover_dns_alive(
                    args.discover_dns,
                    use_bootstrap=not args.discover_dns_no_bootstrap,
                )
                if eps:
                    voice_ip, voice_port = eps[0]["ip"], eps[0]["port"]
                    print(
                        f"  {GREEN}Voice {voice_ip}:{voice_port} "
                        f"method={eps[0].get('method')} "
                        f"bootstrap={eps[0].get('bootstrap')}{RESET}"
                    )
                else:
                    print(f"  {YELLOW}No alive voice — using defaults{RESET}")
            except Exception as e:
                print(f"  {YELLOW}discover-dns error: {e}{RESET}")
        else:
            print(f"\n  {CYAN}[{voice_step}/{steps}] Voice discover skipped{RESET}")

        # ── QUIC HTTP/3 (UDP/443) ──
        if quic_items and not args.tcp_only and not args.no_quic:
            quic_timeout = getattr(args, "quic_timeout", args.timeout)
            print(
                f"\n  {CYAN}[{quic_step}/{steps}] HTTP/3 QUIC "
                f"({len(quic_items)} strategies, timeout={quic_timeout}s)...{RESET}"
            )
            if not supports_http3():
                print(f"  {YELLOW}Skipping QUIC tests — HTTP/3 not supported{RESET}")
            else:
                quic_done = quic_passed = quic_skipped = 0

                async def _one_quic(item: StrategyItem, domain: str):
                    nonlocal quic_done, quic_skipped, quic_passed
                    if stop.is_set():
                        return
                    if args.resume and await db.has_tcp_result(
                        item.label, domain, proto="quic"
                    ):
                        quic_skipped += 1
                        quic_done += 1
                        return
                    r = await runner.test_quic(item, domain, timeout=quic_timeout)
                    quic_done += 1
                    if r.success:
                        quic_passed += 1

                quic_tasks = [_one_quic(item, d) for item in quic_items for d in domains]
                for i in range(0, len(quic_tasks), 200):
                    if stop.is_set():
                        break
                    await asyncio.gather(*quic_tasks[i : i + 200])
                print(
                    f"  {GREEN}QUIC done: {quic_passed} PASS, {quic_skipped} skipped, "
                    f"{quic_done - quic_skipped - quic_passed} FAIL/other{RESET}"
                )
        else:
            print(f"\n  {CYAN}[{quic_step}/{steps}] QUIC skipped{RESET}")

        # ── Pairs ──
        if not args.tcp_only and udp_items:
            print(f"\n  {CYAN}[{pair_step}/{steps}] Pair matrix...{RESET}")
            working_names = await db.get_working_tcp(primary)
            # Prefer coverage winners
            covered = await db.get_best_by_coverage(limit=args.pair_max)
            if covered:
                labels = {c["strategy"] for c in covered}
                working_tcp = [i for i in tcp_items if i.label in labels or i.strategy in labels]
            else:
                working_tcp = [i for i in tcp_items if i.label in working_names]
            # Build fake TcpTestResult-like for pair matrix — need real results
            # Re-use pair API: requires list[TcpTestResult]
            from blockchecks.engine.async_runner import TcpTestResult

            tcp_results = []
            for item in working_tcp[: args.pair_max]:
                tr = TcpTestResult(item=item, domain=primary, success=True)
                tcp_results.append(tr)
            if tcp_results:
                pairs = await runner.test_pair_matrix(
                    tcp_results,
                    udp_items[: max(1, args.pair_max // 2)],
                    primary,
                    voice_ip,
                    voice_port,
                    udp_timeout=args.udp_timeout,
                    udp_bypass=True,
                    fingerprint=fp,
                )
                n_pass = sum(1 for p in pairs if p.overall == "PASS")
                print(f"  Pairs PASS={n_pass}/{len(pairs)}")
            else:
                print(f"  {YELLOW}No working TCP for pairs{RESET}")
        else:
            print(f"\n  {CYAN}[{pair_step}/{steps}] Pairs skipped{RESET}")

        # ── Export ──
        print(f"\n  {CYAN}[{export_step}/{steps}] Export configs...{RESET}")
        result = await export_configs(
            db_path=args.db,
            domain=primary,
            limit=args.export_limit,
            out_dir=args.out_dir,
            isp_interface=args.isp_interface,
            prefix=args.prefix,
            mode=args.mode,
            domains_file=domains_file,
            common_only=not getattr(args, "no_common_only", False),
        )
        print(f"  {GREEN}{result['keenetic']}{RESET}")
        print(f"  {GREEN}{result['raw']}{RESET}")
        print(f"  {GREEN}{result['user_list']}{RESET}")
    finally:
        await runner.stop()

    return 0 if not stop.is_set() else 130


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bs full",
        description="Mass strategy x coverage test + nfqws2 conf export",
    )
    p.add_argument("--db", default="state.db")
    p.add_argument(
        "-d", "--domain", default=None, help="Primary domain (default: first in domains file)"
    )
    p.add_argument(
        "--domains-file",
        default=None,
        help="Default: presets/domains/coverage-tcp.txt (lean)",
    )
    g = p.add_argument_group("domain filter")
    g.add_argument(
        "--allow-unsafe-domains",
        action="store_true",
        help="Do not apply presets/domains/denylist.txt",
    )
    g.add_argument(
        "--zero-pass-warn",
        type=int,
        default=10,
        metavar="N",
        help="Warn if domain has 0%% PASS after N DB results (0=off, default 10)",
    )
    p.add_argument("--tcp-sources", default="standard,custom,configs")
    p.add_argument("--udp-sources", default="custom,standard_udp")
    p.add_argument("--quic-sources", default="standard_quic")
    p.add_argument("--http-sources", default="custom,standard_http")
    p.add_argument("--no-http", action="store_true", help="Skip HTTP :80 strategy phase")
    p.add_argument("--scan-level", default="full", choices=["single", "fast", "full"])
    p.add_argument("--max", type=int, default=0, help="Cap strategies (0=uncapped)")
    p.add_argument("--parallel", type=int, default=4)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--udp-timeout", type=float, default=3.0)
    p.add_argument("--protocol", default="tls12", choices=["tls12", "tls13"])
    p.add_argument("--resume", action="store_true", help="Skip strategy x domain already in DB")
    p.add_argument("--tcp-only", action="store_true")
    p.add_argument("--no-quic", action="store_true")
    p.add_argument("--no-voice", action="store_true")
    p.add_argument("--discover-dns", type=int, default=5)
    p.add_argument("--discover-dns-no-bootstrap", action="store_true")
    p.add_argument("--pair-max", type=int, default=200)
    p.add_argument("--export-limit", type=int, default=3)
    p.add_argument(
        "--no-common-only",
        action="store_true",
        help="Export best per-domain strategies instead of COMMON intersection",
    )
    p.add_argument("--out-dir", default="output")
    p.add_argument("--isp-interface", default="eth3")
    p.add_argument("--prefix", default="/opt/etc/nfqws2")
    p.add_argument("--mode", default="auto", choices=["auto", "list", "all"])
    g = p.add_argument_group("secure DNS")
    g.add_argument("--no-secure-dns", action="store_true", help="Disable DoH pre-resolve")
    g.add_argument("--doh-server", default=None, help="Fixed DoH server URL")
    g.add_argument("--skip-dns-audit", action="store_true")
    g.add_argument("--allow-dns-hijack", action="store_true")
    g = p.add_argument_group("preflight")
    g.add_argument("--skip-ip-block", action="store_true", help="Skip IP-block cross-test")
    g.add_argument(
        "--unblocked-dom",
        default=None,
        help=f"Reference unblocked domain (default: {UNBLOCKED_DOM})",
    )
    g.add_argument("--skip-baseline", action="store_true", help="Skip unblocked baseline check")
    g.add_argument("--skip-port-block", action="store_true", help="Skip TCP port probes")
    g.add_argument("--skip-prolog", action="store_true", help="Skip no-bypass prolog curl")
    g.add_argument(
        "--force",
        action="store_true",
        help="Run strategy tests even if prolog passes (no bypass needed)",
    )
    g.add_argument("--skip-nfqws2-check", action="store_true", help="Skip host nfqws2 detection")
    g.add_argument(
        "--abort-on-nfqws2",
        action="store_true",
        help="Abort if nfqws2 already running on host",
    )
    add_curl_repeats_args(p)
    add_family_gate_args(p)
    add_protocol_phase_args(p)
    g = p.add_argument_group("curl fan-out (B2)")
    g.add_argument(
        "--curl-parallel",
        type=int,
        default=DEFAULT_CURL_PARALLEL,
        metavar="N",
        help=f"Domains per nfqws2 session (1=off, max {MAX_CURL_PARALLEL}, default 1)",
    )
    g = p.add_argument_group("settle profile (B11)")
    g.add_argument(
        "--settle-profile",
        default=None,
        metavar="PATH",
        help="Load settle/curl timings from bench-settle JSON (default: logs/settle_profile.json)",
    )
    g.add_argument(
        "--no-settle-profile",
        action="store_true",
        help="Ignore settle profile even if logs/settle_profile.json exists",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    return asyncio.run(run_full(args))


if __name__ == "__main__":
    sys.exit(main())
