"""bs full — mass strategy×coverage orchestrator + conf export."""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
import time

from colorama import Fore, Style
from colorama import init as colorama_init

from blockchecks.checkers.dns_secure import prepare_dns_for_run
from blockchecks.engine.async_runner import AsyncTestRunner
from blockchecks.engine.config import (
    DEFAULT_VOICE_IP,
    DEFAULT_VOICE_PORT,
    PROJECT_DIR,
    SECURE_DNS_DEFAULT,
    UNBLOCKED_DOM,
)
from blockchecks.engine.db_logger import StateDB, matrix_fingerprint
from blockchecks.engine.matrix_generator import MatrixGenerator, StrategyItem
from blockchecks.engine.preflight import PreflightOptions, run_preflight
from blockchecks.nfconf import export_configs

colorama_init(autoreset=True)
CYAN = Fore.CYAN
GREEN = Fore.GREEN + Style.BRIGHT
YELLOW = Fore.YELLOW
RED = Fore.RED + Style.BRIGHT
RESET = Style.RESET_ALL


def _load_domains(path: str) -> list[str]:
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


def _cap(n: int) -> int:
    """0 / negative → uncapped sentinel for MatrixGenerator slicing."""
    return 999_999 if n <= 0 else n


async def run_full(args) -> int:
    db = StateDB(args.db)
    await db.init()

    domains_file = args.domains_file
    if not domains_file:
        domains_file = os.path.join(PROJECT_DIR, "presets", "domains", "coverage.txt")
    if not os.path.exists(domains_file):
        print(f"{RED}ERROR: domains file not found: {domains_file}{RESET}")
        return 1
    domains = _load_domains(domains_file)
    if not domains:
        print(f"{RED}ERROR: empty domains file{RESET}")
        return 1

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

    max_n = _cap(args.max)
    scan_level = args.scan_level
    parallel = args.parallel

    print(f"\n  {CYAN}blockcheckS — FULL run{RESET}")
    print(f"  Domains:    {len(domains)} from {domains_file}")
    print(f"  Primary:    {primary}")
    print(f"  TCP src:    {tcp_sources}  level={scan_level}  max={args.max or 'uncapped'}")
    print(f"  UDP src:    {udp_sources}")
    print(f"  QUIC src:   {quic_sources}")
    print(f"  Parallel:   {parallel}  resume={bool(args.resume)}")
    print(f"  DB:         {args.db}")

    gen = MatrixGenerator()
    print(f"\n  {CYAN}[1/6] Generating strategies...{RESET}")
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
        quic_items = await gen.generate_udp(
            sources=quic_sources,
            domain=primary,
            scan_level=scan_level,
            max_count=max(30, max_n // 50),
            state_db=db,
        )

    print(f"  TCP={len(tcp_items)}  UDP={len(udp_items)}  QUIC={len(quic_items)}")
    if not tcp_items:
        print(f"{RED}ERROR: no TCP strategies generated{RESET}")
        return 1

    total_tcp_jobs = len(tcp_items) * len(domains)
    eta_sec = total_tcp_jobs * 3.0 / max(parallel, 1)
    print(f"  TCP jobs:   {total_tcp_jobs}  (~ETA {eta_sec / 3600:.1f}h @ ~3s/job)")

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
        print(f"\n  {CYAN}[2/6] TCP × coverage ({len(domains)} domains)...{RESET}")
        done = 0
        skipped = 0
        passed = 0
        t0 = time.perf_counter()
        sem = asyncio.Semaphore(parallel)

        async def _one(item: StrategyItem, domain: str):
            nonlocal done, skipped, passed
            if stop.is_set():
                return
            if args.resume and await db.has_tcp_result(item.label, domain):
                skipped += 1
                done += 1
                return
            async with sem:
                if stop.is_set():
                    return
                r = await runner.test_tcp(item, domain, timeout=args.timeout)
                done += 1
                if r.success:
                    passed += 1
                if done % 50 == 0 or done == total_tcp_jobs:
                    elapsed = time.perf_counter() - t0
                    rate = done / elapsed if elapsed > 0 else 0
                    left = (total_tcp_jobs - done) / rate if rate > 0 else 0
                    print(
                        f"  [{done}/{total_tcp_jobs}] pass={passed} skip={skipped} "
                        f"{rate:.2f}/s ETA {left / 60:.0f}m"
                    )

        tasks = [_one(item, domain) for item in tcp_items for domain in domains]
        # Chunk gather to avoid huge task list memory
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

        voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
        if not args.tcp_only and not args.no_voice:
            print(f"\n  {CYAN}[3/6] Voice discover-dns...{RESET}")
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
            print(f"\n  {CYAN}[3/6] Voice discover skipped{RESET}")

        # ── QUIC (best-effort UDP/443) ──
        if quic_items and not args.tcp_only and not args.no_quic:
            print(f"\n  {CYAN}[4/6] QUIC strategies ({len(quic_items)})...{RESET}")
            quic_pass = 0
            for item in quic_items:
                if stop.is_set():
                    break
                # Store as udp proto for export pickup; probe may timeout
                r = await runner.test_udp(item, primary, 443, timeout=args.udp_timeout)
                if r.success:
                    quic_pass += 1
            print(f"  QUIC PASS={quic_pass}/{len(quic_items)} (export uses defaults if 0)")
        else:
            print(f"\n  {CYAN}[4/6] QUIC skipped{RESET}")

        # ── Pairs ──
        if not args.tcp_only and udp_items:
            print(f"\n  {CYAN}[5/6] Pair matrix...{RESET}")
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
            print(f"\n  {CYAN}[5/6] Pairs skipped{RESET}")

        # ── Export ──
        print(f"\n  {CYAN}[6/6] Export configs...{RESET}")
        result = await export_configs(
            db_path=args.db,
            domain=primary,
            limit=args.export_limit,
            out_dir=args.out_dir,
            isp_interface=args.isp_interface,
            prefix=args.prefix,
            mode=args.mode,
            domains_file=domains_file,
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
    p.add_argument("--domains-file", default=None, help="Default: presets/domains/coverage.txt")
    p.add_argument("--tcp-sources", default="standard,custom,configs")
    p.add_argument("--udp-sources", default="custom,standard_udp")
    p.add_argument("--quic-sources", default="standard_quic")
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
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    return asyncio.run(run_full(args))


if __name__ == "__main__":
    sys.exit(main())
