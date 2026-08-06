"""Phase helpers for ``main.run_full`` (bs full orchestrator)."""

from __future__ import annotations

import asyncio
import signal
import time
from dataclasses import dataclass, field
from typing import Any

from colorama import Fore, Style

from blockchecks.checkers.curl_probe import repeats_from_args
from blockchecks.checkers.dns_secure import prepare_dns_for_run
from blockchecks.checkers.http3 import supports_http3
from blockchecks.engine.adaptive_runner import (
    build_adaptive_queue,
    persist_adaptive_weights,
    run_adaptive_tcp,
)
from blockchecks.engine.async_runner import AsyncTestRunner, tcp_results_from_details
from blockchecks.engine.config import (
    DEFAULT_CURL_PARALLEL,
    DEFAULT_VOICE_IP,
    DEFAULT_VOICE_PORT,
    MAX_CURL_PARALLEL,
    SECURE_DNS_DEFAULT,
)
from blockchecks.engine.domain_loader import (
    DEFAULT_DOMAINS_FILE,
    format_skip_summary,
    load_domains,
    warn_zero_pass_domains,
)
from blockchecks.engine.family_needs import run_tcp_with_family_gates
from blockchecks.engine.matrix_generator import MatrixGenerator, StrategyItem
from blockchecks.engine.preflight import PreflightOptions
from blockchecks.engine.run_deadline import RunDeadline
from blockchecks.engine.run_finalize import (
    finalize_db_and_weights,
    maybe_export_configs,
    write_run_summary,
)
from blockchecks.engine.settle_profile import auto_load_profile, load_profile
from blockchecks.engine.store import (
    DEFAULT_DB_BATCH,
    fingerprint_mismatch,
    matrix_fingerprint,
    open_run_store,
)
from blockchecks.engine.tcp_fanout import fanout_allowed, fanout_batches

CYAN = Fore.CYAN
GREEN = Fore.GREEN + Style.BRIGHT
YELLOW = Fore.YELLOW
RED = Fore.RED + Style.BRIGHT
RESET = Style.RESET_ALL


def cap_strategy_count(n: int) -> int:
    """0 / negative → uncapped sentinel for MatrixGenerator slicing."""
    return 999_999 if n <= 0 else n


def apply_gp_protocol_flags(args) -> bool:
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


def split_sources(value: str) -> list[str]:
    return [s for s in value.split(",") if s]


@dataclass
class FullRunContext:
    args: Any
    db: Any
    domains_file: str
    domains: list[str]
    primary: str
    secure_dns: bool
    dns_cache: Any
    dns_audits: list[Any]
    skip_tcp_tls: bool
    tcp_sources: list[str]
    udp_sources: list[str]
    quic_sources: list[str]
    http_sources: list[str]
    max_n: int
    scan_level: str
    parallel: int
    steps: int
    tcp_items: list[StrategyItem] = field(default_factory=list)
    udp_items: list[StrategyItem] = field(default_factory=list)
    quic_items: list[StrategyItem] = field(default_factory=list)
    http_items: list[StrategyItem] = field(default_factory=list)
    total_tcp_jobs: int = 0
    use_adaptive: bool = False
    curl_parallel: int = 1
    use_family_gates: bool = False
    use_fanout: bool = False
    fanout_note: str = ""
    settle_profile: Any = None
    fp: str = ""
    runner: AsyncTestRunner | None = None
    stop: asyncio.Event = field(default_factory=asyncio.Event)
    deadline: RunDeadline | None = None
    signal_interrupted: bool = False
    aq_result: Any = None
    voice_eps: list = field(default_factory=list)
    repeats: int = 0
    parallel_repeats: int = 0
    repeats_mode: str = ""
    quick_break: bool = False


@dataclass
class TcpProgress:
    total: int
    done: int = 0
    skipped: int = 0
    passed: int = 0
    t0: float = field(default_factory=time.perf_counter)

    def report(self) -> None:
        if self.done % 50 == 0 or self.done == self.total:
            elapsed = time.perf_counter() - self.t0
            rate = self.done / elapsed if elapsed > 0 else 0
            left = (self.total - self.done) / rate if rate > 0 else 0
            print(
                f"  [{self.done}/{self.total}] pass={self.passed} skip={self.skipped} "
                f"{rate:.2f}/s ETA {left / 60:.0f}m"
            )


async def open_full_run_db(args) -> Any:
    db = open_run_store(
        args.db,
        batch_size=int(getattr(args, "db_batch", DEFAULT_DB_BATCH)),
    )
    await db.init()
    return db


def load_run_domains(args) -> tuple[list[str], str, int | None]:
    domains_file = args.domains_file or DEFAULT_DOMAINS_FILE
    try:
        loaded = load_domains(
            domains_file,
            allow_unsafe=getattr(args, "allow_unsafe_domains", False),
        )
    except FileNotFoundError:
        print(f"{RED}ERROR: domains file not found: {domains_file}{RESET}")
        return [], domains_file, 1
    domains = loaded.domains
    if not domains:
        print(
            f"{RED}ERROR: no domains left after denylist filter (use --allow-unsafe-domains){RESET}"
        )
        return [], domains_file, 1
    if loaded.skipped:
        print(f"  {YELLOW}{format_skip_summary(loaded.skipped)}{RESET}")
    return domains, domains_file, None


def prepare_run_dns(args, domains: list[str]) -> tuple[Any, list[Any], int | None]:
    from blockchecks.data_block.provider import provider_name

    provider_name(allow_detect=True)
    secure_dns = SECURE_DNS_DEFAULT and not getattr(args, "no_secure_dns", False)
    dns_cache, dns_audits, dns_rc = prepare_dns_for_run(
        domains,
        secure_dns=secure_dns,
        skip_audit=getattr(args, "skip_dns_audit", False),
        allow_hijack=getattr(args, "allow_dns_hijack", False),
        doh_server=getattr(args, "doh_server", None) or None,
    )
    if dns_rc:
        return dns_cache, dns_audits, dns_rc
    return dns_cache, dns_audits, None


async def run_preflight_filter(
    args,
    domains: list[str],
    primary: str,
    dns_cache: Any,
    store: Any = None,
) -> tuple[list[str], str, int | None]:
    from blockchecks.engine.preflight import run_preflight_async

    preflight = await run_preflight_async(
        domains,
        PreflightOptions.from_args(args, dns_cache=dns_cache, store=store),
    )
    if preflight.exit_code:
        print(f"{RED}ERROR: preflight failed: {preflight.error}{RESET}")
        return domains, primary, preflight.exit_code
    if preflight.skip_domains:
        skipped = sorted(preflight.skip_domains)
        print(f"  {YELLOW}Prolog skip: {', '.join(skipped)}{RESET}")
        domains = [d for d in domains if d not in preflight.skip_domains]
        if not domains:
            print(f"{YELLOW}All domains work without bypass — nothing to test{RESET}")
            return domains, primary, 0
        if primary in preflight.skip_domains:
            primary = domains[0]
    return domains, primary, None


def build_full_run_context(
    args,
    db: Any,
    domains: list[str],
    domains_file: str,
    dns_cache: Any,
    dns_audits: list[Any],
) -> FullRunContext:
    secure_dns = SECURE_DNS_DEFAULT and not getattr(args, "no_secure_dns", False)
    skip_tcp_tls = apply_gp_protocol_flags(args)
    primary = args.domain or domains[0]
    steps = 7 if not getattr(args, "no_http", False) else 6
    repeats, parallel_repeats, repeats_mode, quick_break = repeats_from_args(args)
    return FullRunContext(
        args=args,
        db=db,
        domains_file=domains_file,
        domains=domains,
        primary=primary,
        secure_dns=secure_dns,
        dns_cache=dns_cache,
        dns_audits=dns_audits,
        skip_tcp_tls=skip_tcp_tls,
        tcp_sources=split_sources(args.tcp_sources),
        udp_sources=split_sources(args.udp_sources),
        quic_sources=split_sources(args.quic_sources),
        http_sources=split_sources(getattr(args, "http_sources", "custom,standard_http")),
        max_n=cap_strategy_count(args.max),
        scan_level=args.scan_level,
        parallel=args.parallel,
        steps=steps,
        repeats=repeats,
        parallel_repeats=parallel_repeats,
        repeats_mode=repeats_mode,
        quick_break=quick_break,
    )


def print_full_run_banner(ctx: FullRunContext) -> None:
    args = ctx.args
    print(f"\n  {CYAN}blockcheckS — FULL run{RESET}")
    print(f"  Domains:    {len(ctx.domains)} from {ctx.domains_file}")
    print(f"  Primary:    {ctx.primary}")
    print(f"  TCP src:    {ctx.tcp_sources}  level={ctx.scan_level}  max={args.max or 'uncapped'}")
    if not getattr(args, "no_http", False):
        print(f"  HTTP src:   {ctx.http_sources}")
    print(f"  UDP src:    {ctx.udp_sources}")
    print(f"  QUIC src:   {ctx.quic_sources}")
    print(f"  Parallel:   {ctx.parallel}  resume={bool(args.resume)}")
    if not getattr(args, "no_quic", False) and not args.tcp_only:
        if supports_http3():
            print(f"  HTTP/3:     {GREEN}curl v3only supported{RESET}")
        else:
            print(f"  {YELLOW}HTTP/3: curl lacks --http3-only — QUIC phase will fail{RESET}")
    print(f"  DB:         {args.db}")


async def generate_strategy_items(ctx: FullRunContext, gen: MatrixGenerator) -> int | None:
    args = ctx.args
    print(f"\n  {CYAN}[1/{ctx.steps}] Generating strategies...{RESET}")
    if not ctx.skip_tcp_tls:
        ctx.tcp_items = await gen.generate_tcp(
            sources=ctx.tcp_sources,
            domain=ctx.primary,
            scan_level=ctx.scan_level,
            max_count=ctx.max_n,
            state_db=ctx.db,
            protocol=args.protocol,
        )
    if not args.tcp_only:
        ctx.udp_items = await gen.generate_udp(
            sources=ctx.udp_sources,
            domain=ctx.primary,
            scan_level=ctx.scan_level,
            max_count=max(50, ctx.max_n // 20),
            state_db=ctx.db,
        )
    if not args.no_quic and not args.tcp_only:
        ctx.quic_items = await gen.generate_quic(
            sources=ctx.quic_sources,
            domain=ctx.primary,
            scan_level=ctx.scan_level,
            max_count=max(30, ctx.max_n // 50) if ctx.max_n else 50,
            state_db=ctx.db,
        )
    if not getattr(args, "no_http", False):
        ctx.http_items = await gen.generate_http(
            sources=ctx.http_sources,
            domain=ctx.primary,
            scan_level=ctx.scan_level,
            max_count=max(30, ctx.max_n // 20) if ctx.max_n else 50,
            state_db=ctx.db,
        )

    print(
        f"  TCP={len(ctx.tcp_items)}  HTTP={len(ctx.http_items)}  "
        f"UDP={len(ctx.udp_items)}  QUIC={len(ctx.quic_items)}"
    )
    if ctx.skip_tcp_tls:
        print(
            f"  {YELLOW}TCP TLS phase skipped (--tls{args.protocol.replace('tls', '')}-off){RESET}"
        )
    elif not ctx.tcp_items:
        print(f"{RED}ERROR: no TCP strategies generated{RESET}")
        return 1

    ctx.total_tcp_jobs = len(ctx.tcp_items) * len(ctx.domains) if ctx.tcp_items else 0
    if ctx.total_tcp_jobs:
        eta_sec = ctx.total_tcp_jobs * 3.0 / max(ctx.parallel, 1)
        print(f"  TCP jobs:   {ctx.total_tcp_jobs}  (~ETA {eta_sec / 3600:.1f}h @ ~3s/job)")
    return None


def configure_tcp_execution(ctx: FullRunContext) -> None:
    args = ctx.args
    use_adaptive = bool(getattr(args, "adaptive", False) or getattr(args, "fan_out", False))
    curl_parallel = max(
        1, min(getattr(args, "curl_parallel", DEFAULT_CURL_PARALLEL), MAX_CURL_PARALLEL)
    )
    if getattr(args, "fan_out", False) and curl_parallel <= 1:
        curl_parallel = min(max(4, DEFAULT_CURL_PARALLEL), MAX_CURL_PARALLEL)
    use_family_gates = (
        ctx.scan_level != "full"
        and not getattr(args, "no_family_gates", False)
        and not use_adaptive
        and any(
            s in ("standard", "fake", "hostfake", "faked", "fake_multi", "fake_faked")
            for s in ctx.tcp_sources
        )
    )
    fanout_ok, fanout_note = fanout_allowed(
        curl_parallel=curl_parallel,
        use_family_gates=use_family_gates,
        domains=ctx.domains,
        protocol=args.protocol,
    )
    use_fanout = fanout_ok and curl_parallel > 1 and not use_adaptive
    if curl_parallel > 1 and not fanout_ok and fanout_note.startswith("family"):
        print(f"  {YELLOW}curl-parallel disabled: {fanout_note}{RESET}")
        curl_parallel = 1
    elif use_fanout:
        print(f"  {GREEN}curl-parallel: {curl_parallel}{RESET} (B2 fan-out)")
        if fanout_note:
            print(f"  {YELLOW}{fanout_note}{RESET}")
    if use_adaptive:
        eps = getattr(args, "adaptive_epsilon", 0.1)
        print(
            f"  {GREEN}Adaptive queue:{RESET} ε={eps}"
            + (f", curl-parallel={curl_parallel} (AQ5+B2)" if curl_parallel > 1 else "")
        )
    if use_family_gates:
        print(f"  Family gates: {GREEN}on{RESET} (BC2-6 need_* chain)")

    ctx.use_adaptive = use_adaptive
    ctx.curl_parallel = curl_parallel
    ctx.use_family_gates = use_family_gates
    ctx.use_fanout = use_fanout
    ctx.fanout_note = fanout_note


def resolve_settle_profile(args) -> Any:
    if getattr(args, "no_settle_profile", False):
        return None
    if getattr(args, "settle_profile", None):
        return load_profile(args.settle_profile)
    return auto_load_profile()


def print_settle_profile(settle_profile: Any) -> None:
    if settle_profile and settle_profile.source_path:
        d = settle_profile.defaults
        hint = (
            f"settle={d.settle_max}s curl={d.curl_timeout}s"
            if d
            else f"{len(settle_profile.strategies)} strategies"
        )
        print(f"  {GREEN}Settle profile:{RESET} {settle_profile.source_path} ({hint})")


def build_matrix_fingerprint(ctx: FullRunContext) -> str:
    fp = matrix_fingerprint(
        [i.strategy for i in ctx.tcp_items],
        [i.strategy for i in ctx.udp_items],
        scan_level=ctx.scan_level,
        max_count=ctx.args.max,
    )
    print(f"  Fingerprint:{fp}")
    return fp


def build_async_runner(ctx: FullRunContext) -> AsyncTestRunner:
    args = ctx.args
    return AsyncTestRunner(
        pool_size=ctx.parallel,
        db=ctx.db,
        secure_dns=ctx.secure_dns,
        dns_cache=ctx.dns_cache,
        dns_audit={r.domain: r for r in ctx.dns_audits},
        repeats=ctx.repeats,
        parallel_repeats=ctx.parallel_repeats,
        repeats_mode=ctx.repeats_mode,
        quick_break=ctx.quick_break,
        try_wssize=not getattr(args, "no_wssize", False)
        and getattr(args, "protocol", "tls12") == "tls12",
        settle_profile=ctx.settle_profile,
        lua_bridge=bool(getattr(args, "lua_bridge", False)),
        bridge_batch=int(getattr(args, "bridge_batch", 500) or 500),
        lua_bridge_compare=bool(getattr(args, "lua_bridge_compare", False)),
        lua_extra=list(getattr(args, "lua_extra", None) or []),
    )


def arm_stop_handlers(ctx: FullRunContext) -> None:
    def _stop(*_a):
        ctx.signal_interrupted = True
        if ctx.deadline and not ctx.deadline.triggered:
            ctx.deadline.reason = "signal"
        ctx.stop.set()

    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, _stop)
        loop.add_signal_handler(signal.SIGTERM, _stop)
    except (NotImplementedError, RuntimeError):
        signal.signal(signal.SIGINT, lambda *_: _stop())


async def arm_run_deadline(ctx: FullRunContext) -> None:
    ctx.deadline = RunDeadline.from_args(ctx.stop, ctx.args)
    if ctx.deadline:
        ctx.deadline.arm()
        await ctx.deadline.start_background()
        print(f"  Time limit: {ctx.deadline.budget_label()}")


def print_optional_phases_skip(ctx: FullRunContext) -> None:
    if ctx.deadline and ctx.deadline.triggered:
        print(
            f"\n  {YELLOW}TIME LIMIT reached ({ctx.deadline.budget_label()})"
            f" — skipping optional phases{RESET}"
        )
    elif ctx.signal_interrupted:
        print(f"\n  {YELLOW}Stopped — skipping optional phases{RESET}")


async def _run_tcp_adaptive(ctx: FullRunContext, progress: TcpProgress) -> None:
    args = ctx.args

    # Bulk-load completed keys once — per-job has_tcp_result × 100k+ jobs
    # opens that many aiosqlite threads and hits RLIMIT (EMFILE / can't start thread).
    completed_tcp: set[tuple[str, str]] = set()
    if args.resume and ctx.db is not None:
        completed_tcp = await ctx.db.get_completed_tcp_keys()

    async def _resume_job(job):
        return (job.item.label, job.domain) in completed_tcp

    queue, skipped = await build_adaptive_queue(
        ctx.tcp_items,
        ctx.domains,
        ctx.db,
        epsilon=getattr(args, "adaptive_epsilon", 0.1),
        load_weights=not getattr(args, "no_adaptive_weights", False),
        resume_check=_resume_job if args.resume else None,
    )
    progress.done = skipped
    progress.report()
    print(f"  AQ pending jobs: {len(queue)} (+{skipped} resume skip)")

    def _progress(d: int, s: int, p: int):
        progress.done, progress.skipped, progress.passed = d, s, p
        progress.report()

    ctx.aq_result = await run_adaptive_tcp(
        ctx.runner,
        queue,
        timeout=args.timeout,
        curl_parallel=ctx.curl_parallel,
        protocol=args.protocol,
        disable_ech=bool(getattr(args, "disable_ech", False)),
        stop_event=ctx.stop,
        on_progress=_progress,
        lua_bridge=bool(getattr(args, "lua_bridge", False)),
        bridge_batch=int(getattr(args, "bridge_batch", 500) or 500),
        workers=max(1, int(getattr(args, "parallel", 4) or 4)),
    )
    progress.done = skipped + ctx.aq_result.done
    progress.passed = ctx.aq_result.passed
    if not getattr(args, "no_adaptive_weights", False):
        await persist_adaptive_weights(ctx.db, ctx.aq_result.weights)
    m = ctx.aq_result.metrics
    if m.time_to_first_pass is not None:
        print(
            f"  AQ first PASS: {m.time_to_first_pass:.1f}s  fan-out enqueued: {m.fanout_enqueued}"
        )
    if m.half_mark_jobs and ctx.aq_result.passed:
        pct = 100.0 * m.passes_before_half / ctx.aq_result.passed
        print(
            f"  AQ passes before 50% jobs: {m.passes_before_half} "
            f"({pct:.0f}% of {ctx.aq_result.passed} total passes)"
        )


async def _run_tcp_family_gates(ctx: FullRunContext, progress: TcpProgress) -> None:
    args = ctx.args

    async def _run_domain(domain: str):
        if ctx.stop.is_set():
            return

        async def _resume(label: str, dom: str) -> bool:
            return bool(args.resume and await ctx.db.has_tcp_result(label, dom))

        _, d_done, d_skip, d_pass = await run_tcp_with_family_gates(
            ctx.runner,
            ctx.tcp_items,
            domain,
            scan_level=ctx.scan_level,
            timeout=args.timeout,
            stop_event=ctx.stop,
            resume_check=_resume if args.resume else None,
        )
        progress.done += d_done
        progress.skipped += d_skip
        progress.passed += d_pass
        progress.report()

    for domain in ctx.domains:
        if ctx.stop.is_set():
            print(f"  {YELLOW}Stopped by signal{RESET}")
            break
        await _run_domain(domain)


async def _run_tcp_fanout(ctx: FullRunContext, progress: TcpProgress) -> None:
    args = ctx.args
    if getattr(args, "lua_bridge", False):
        from blockchecks.engine.batch_probe import warn_fanout_bridge_once

        warn_fanout_bridge_once()

    async def _one_strategy(item: StrategyItem):
        if ctx.stop.is_set():
            return
        pending = [
            d
            for d in ctx.domains
            if not (args.resume and await ctx.db.has_tcp_result(item.label, d))
        ]
        progress.skipped += len(ctx.domains) - len(pending)
        progress.done += len(ctx.domains) - len(pending)
        if not pending:
            return
        batches = fanout_batches(
            pending,
            protocol=args.protocol,
            curl_parallel=ctx.curl_parallel,
        )
        for batch in batches:
            if ctx.stop.is_set():
                return
            batch_results = await ctx.runner.test_tcp_domains(
                item, batch, timeout=args.timeout, curl_parallel=len(batch)
            )
            for r in batch_results:
                progress.done += 1
                if r.success:
                    progress.passed += 1
                if ctx.stop.is_set():
                    progress.report()
                    return
            progress.report()

    tasks = [_one_strategy(item) for item in ctx.tcp_items]
    chunk = max(1, ctx.parallel)
    for i in range(0, len(tasks), chunk):
        if ctx.stop.is_set():
            print(f"  {YELLOW}Stopped by signal{RESET}")
            break
        await asyncio.gather(*tasks[i : i + chunk])


async def _run_tcp_sequential(ctx: FullRunContext, progress: TcpProgress) -> None:
    args = ctx.args
    if getattr(args, "lua_bridge", False):
        await _run_tcp_sequential_bridge(ctx, progress)
        return

    async def _one(item: StrategyItem, domain: str):
        if ctx.stop.is_set():
            return
        if args.resume and await ctx.db.has_tcp_result(item.label, domain):
            progress.skipped += 1
            progress.done += 1
            return
        r = await ctx.runner.test_tcp(item, domain, timeout=args.timeout)
        progress.done += 1
        if r.success:
            progress.passed += 1
        progress.report()

    tasks = [_one(item, domain) for item in ctx.tcp_items for domain in ctx.domains]
    chunk = 200
    for i in range(0, len(tasks), chunk):
        if ctx.stop.is_set():
            print(f"  {YELLOW}Stopped by signal{RESET}")
            break
        await asyncio.gather(*tasks[i : i + chunk])


async def _run_tcp_sequential_bridge(ctx: FullRunContext, progress: TcpProgress) -> None:
    """Sequential domain×strategy with lua_bridge batch service."""
    from blockchecks.engine.batch_probe import BatchScheduler

    args = ctx.args
    scheduler = BatchScheduler(ctx.runner.bridge_batch)

    for domain in ctx.domains:
        if ctx.stop.is_set():
            print(f"  {YELLOW}Stopped by signal{RESET}")
            break
        pending: list[StrategyItem] = []
        for item in ctx.tcp_items:
            if args.resume and await ctx.db.has_tcp_result(item.label, domain):
                progress.skipped += 1
                progress.done += 1
                continue
            pending.append(item)
        progress.report()
        for batch in scheduler.iter_batches(pending):
            if ctx.stop.is_set():
                print(f"  {YELLOW}Stopped by signal{RESET}")
                break
            results = await ctx.runner._run_probe_batch(
                batch, domain, args.timeout, "lua_bridge"
            )
            for r in results:
                progress.done += 1
                if r.success:
                    progress.passed += 1
            progress.report()


async def run_tcp_coverage_phase(ctx: FullRunContext) -> None:
    if not ctx.tcp_items:
        print(f"\n  {CYAN}[2/{ctx.steps}] TCP × coverage skipped{RESET}")
        return

    print(f"\n  {CYAN}[2/{ctx.steps}] TCP × coverage ({len(ctx.domains)} domains)...{RESET}")
    progress = TcpProgress(total=ctx.total_tcp_jobs)

    if ctx.use_adaptive:
        await _run_tcp_adaptive(ctx, progress)
    elif ctx.use_family_gates:
        await _run_tcp_family_gates(ctx, progress)
    elif ctx.use_fanout:
        await _run_tcp_fanout(ctx, progress)
    else:
        await _run_tcp_sequential(ctx, progress)

    print(
        f"  {GREEN}TCP done: {progress.passed} PASS, {progress.skipped} skipped, "
        f"{progress.done - progress.skipped - progress.passed} FAIL/other{RESET}"
    )
    zero_warn = getattr(ctx.args, "zero_pass_warn", 10)
    if zero_warn > 0:
        zero_domains = await warn_zero_pass_domains(
            ctx.db, ctx.domains, min_results=zero_warn, protos=("tcp",)
        )
        if zero_domains:
            print(
                f"  {YELLOW}WARN: 0% PASS after {zero_warn}+ runs: {', '.join(zero_domains)}{RESET}"
            )


async def run_http_phase(ctx: FullRunContext) -> None:
    args = ctx.args
    if not ctx.stop.is_set() and ctx.http_items and not getattr(args, "no_http", False):
        print(f"\n  {CYAN}[3/{ctx.steps}] HTTP :80 ({len(ctx.http_items)} strategies)...{RESET}")
        http_done = http_passed = http_skipped = 0

        async def _one_http(item: StrategyItem, domain: str):
            nonlocal http_done, http_skipped, http_passed
            if ctx.stop.is_set():
                return
            if args.resume and await ctx.db.has_tcp_result(item.label, domain, proto="http"):
                http_skipped += 1
                http_done += 1
                return
            r = await ctx.runner.test_tcp(item, domain, timeout=args.timeout)
            http_done += 1
            if r.success:
                http_passed += 1

        http_tasks = [_one_http(item, d) for item in ctx.http_items for d in ctx.domains]
        for i in range(0, len(http_tasks), 200):
            if ctx.stop.is_set():
                break
            await asyncio.gather(*http_tasks[i : i + 200])
        print(
            f"  {GREEN}HTTP done: {http_passed} PASS, {http_skipped} skipped, "
            f"{http_done - http_skipped - http_passed} FAIL/other{RESET}"
        )
    elif not ctx.stop.is_set() and not getattr(args, "no_http", False):
        print(f"\n  {CYAN}[3/{ctx.steps}] HTTP skipped (no strategies){RESET}")


def _voice_step(ctx: FullRunContext) -> int:
    return 4 if ctx.steps == 7 else 3


def _quic_step(ctx: FullRunContext) -> int:
    return 5 if ctx.steps == 7 else 4


def _pair_step(ctx: FullRunContext) -> int:
    return 6 if ctx.steps == 7 else 5


async def discover_voice_endpoint(ctx: FullRunContext) -> tuple[str, int]:
    args = ctx.args
    voice_step = _voice_step(ctx)
    voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
    if not ctx.stop.is_set() and not args.tcp_only and not args.no_voice:
        print(f"\n  {CYAN}[{voice_step}/{ctx.steps}] Voice discover-dns...{RESET}")
        try:
            from blockchecks.checkers.voice_dns import discover_dns_alive

            eps = await discover_dns_alive(
                args.discover_dns,
                use_bootstrap=not args.discover_dns_no_bootstrap,
            )
            if eps:
                ctx.voice_eps = eps
                voice_ip, voice_port = eps[0]["ip"], eps[0]["port"]
                print(
                    f"  {GREEN}Voice {voice_ip}:{voice_port} "
                    f"({len(eps)} endpoints) "
                    f"method={eps[0].get('method')} "
                    f"bootstrap={eps[0].get('bootstrap')}{RESET}"
                )
                for ep in eps[1:3]:
                    print(f"  {GREEN}  + {ep['ip']}:{ep['port']}{RESET}")
                if len(eps) > 3:
                    print(f"  {GREEN}  ... and {len(eps) - 3} more{RESET}")
            else:
                print(f"  {YELLOW}No alive voice — using defaults{RESET}")
        except Exception as e:
            print(f"  {YELLOW}discover-dns error: {e}{RESET}")
    elif not ctx.stop.is_set():
        print(f"\n  {CYAN}[{voice_step}/{ctx.steps}] Voice discover skipped{RESET}")
    return voice_ip, voice_port


async def run_quic_phase(ctx: FullRunContext) -> None:
    args = ctx.args
    quic_step = _quic_step(ctx)
    if not ctx.stop.is_set() and ctx.quic_items and not args.tcp_only and not args.no_quic:
        quic_timeout = getattr(args, "quic_timeout", args.timeout)
        print(
            f"\n  {CYAN}[{quic_step}/{ctx.steps}] HTTP/3 QUIC "
            f"({len(ctx.quic_items)} strategies, timeout={quic_timeout}s)...{RESET}"
        )
        if not supports_http3():
            print(f"  {YELLOW}Skipping QUIC tests — HTTP/3 not supported{RESET}")
            return

        quic_done = quic_passed = quic_skipped = 0

        async def _one_quic(item: StrategyItem, domain: str):
            nonlocal quic_done, quic_skipped, quic_passed
            if ctx.stop.is_set():
                return
            if args.resume and await ctx.db.has_tcp_result(item.label, domain, proto="quic"):
                quic_skipped += 1
                quic_done += 1
                return
            r = await ctx.runner.test_quic(item, domain, timeout=quic_timeout)
            quic_done += 1
            if r.success:
                quic_passed += 1

        quic_tasks = [_one_quic(item, d) for item in ctx.quic_items for d in ctx.domains]
        for i in range(0, len(quic_tasks), 200):
            if ctx.stop.is_set():
                break
            await asyncio.gather(*quic_tasks[i : i + 200])
        print(
            f"  {GREEN}QUIC done: {quic_passed} PASS, {quic_skipped} skipped, "
            f"{quic_done - quic_skipped - quic_passed} FAIL/other{RESET}"
        )
    elif not ctx.stop.is_set():
        print(f"\n  {CYAN}[{quic_step}/{ctx.steps}] QUIC skipped{RESET}")


async def run_pairs_phase(
    ctx: FullRunContext,
    voice_ip: str,
    voice_port: int,
) -> None:
    args = ctx.args
    pair_step = _pair_step(ctx)
    if not ctx.stop.is_set() and not args.tcp_only and ctx.udp_items:
        print(f"\n  {CYAN}[{pair_step}/{ctx.steps}] Pair matrix...{RESET}")
        details = await ctx.db.get_working_tcp_details(ctx.primary)
        by_status = {d["name"]: d for d in details}
        covered = await ctx.db.get_best_by_coverage(limit=args.pair_max)
        if covered:
            labels = {c["strategy"] for c in covered}
            selected = [i for i in ctx.tcp_items if i.label in labels or i.strategy in labels]
            details = [
                by_status.get(
                    i.label,
                    {"name": i.label, "status": "PASS", "latency_ms": 0},
                )
                for i in selected
            ]
        by_label = {i.label: i for i in ctx.tcp_items}
        for i in ctx.tcp_items:
            by_label.setdefault(i.strategy, i)
        tcp_results = tcp_results_from_details(by_label, details, ctx.primary)[: args.pair_max]
        if tcp_results:
            resume_from = None
            if args.resume:
                resume_from = await ctx.db.latest_checkpoint()
                if resume_from and fingerprint_mismatch(resume_from.fingerprint, ctx.fp):
                    print(
                        f"  {YELLOW}Pair checkpoint fp mismatch "
                        f"({resume_from.fingerprint}≠{ctx.fp}) — full pair re-run{RESET}"
                    )
                    resume_from = None
            from blockchecks.checkers.voice_dns import pair_log_domain, resolve_voice_targets

            targets = resolve_voice_targets(voice_ip, voice_port, ctx.voice_eps)
            multi = len(targets) > 1
            if multi:
                print(f"  {YELLOW}Multi-EP fan-out: {len(targets)} endpoints{RESET}")
            pairs = []
            for ip, port in targets:
                log_dom = pair_log_domain(ctx.primary, ip, port, multi=multi)
                if multi:
                    print(f"  {CYAN}pairs ep={ip}:{port}{RESET}")
                batch = await ctx.runner.test_pair_matrix(
                    tcp_results,
                    ctx.udp_items[: max(1, args.pair_max // 2)],
                    ctx.primary,
                    ip,
                    port,
                    udp_timeout=args.udp_timeout,
                    udp_bypass=True,
                    resume_from=resume_from,
                    fingerprint=ctx.fp,
                    pair_domain=log_dom if multi else None,
                )
                pairs.extend(batch)
            n_pass = sum(1 for p in pairs if p.overall == "PASS")
            print(f"  Pairs PASS={n_pass}/{len(pairs)}")
        else:
            print(f"  {YELLOW}No working TCP for pairs{RESET}")
    elif not ctx.stop.is_set():
        print(f"\n  {CYAN}[{pair_step}/{ctx.steps}] Pairs skipped{RESET}")


async def cleanup_runner(ctx: FullRunContext) -> None:
    if ctx.deadline:
        await ctx.deadline.cancel()
    await finalize_db_and_weights(ctx.db, save_weights=False)
    if ctx.runner:
        await ctx.runner.stop()


def print_aq_stop_metrics(ctx: FullRunContext) -> None:
    if not ctx.aq_result:
        return
    m = ctx.aq_result.metrics
    if ctx.stop.is_set() and m.time_to_first_pass is not None:
        print(f"  AQ first PASS: {m.time_to_first_pass:.1f}s")
    if ctx.stop.is_set() and m.half_mark_jobs and ctx.aq_result.passed:
        pct = 100.0 * m.passes_before_half / ctx.aq_result.passed
        print(
            f"  AQ passes before 50% jobs: {m.passes_before_half} "
            f"({pct:.0f}% of {ctx.aq_result.passed} total passes)"
        )


async def export_and_summarize(ctx: FullRunContext) -> int:
    from blockchecks.engine.run_finalize import run_exit_code
    from blockchecks.engine.run_finalize import maybe_write_best_config_data_block

    await maybe_write_best_config_data_block()

    export_result = await maybe_export_configs(
        ctx.db,
        ctx.args,
        primary=ctx.primary,
        domains_file=ctx.domains_file,
        stop_set=ctx.stop.is_set(),
        deadline=ctx.deadline,
    )
    if export_result:
        print(f"\n  {CYAN}Export configs...{RESET}")
        print(f"  {GREEN}{export_result['keenetic']}{RESET}")
        print(f"  {GREEN}{export_result['raw']}{RESET}")
        print(f"  {GREEN}{export_result['user_list']}{RESET}")

    print_aq_stop_metrics(ctx)

    summary_payload: dict = {
        "command": "full",
        "deadline_sec": ctx.deadline.budget_sec if ctx.deadline else None,
        "stopped_reason": (
            ctx.deadline.reason
            if ctx.deadline and ctx.deadline.triggered
            else ("signal" if ctx.signal_interrupted else None)
        ),
        "db_path": ctx.args.db,
        "export_paths": export_result,
        "domains_file": ctx.domains_file,
        "primary": ctx.primary,
    }
    if ctx.aq_result:
        summary_payload["jobs_done"] = ctx.aq_result.done
        summary_payload["passed"] = ctx.aq_result.passed
        summary_payload["aq_metrics"] = {
            "time_to_first_pass": ctx.aq_result.metrics.time_to_first_pass,
            "fanout_enqueued": ctx.aq_result.metrics.fanout_enqueued,
            "passes_before_half": ctx.aq_result.metrics.passes_before_half,
            "half_mark_jobs": ctx.aq_result.metrics.half_mark_jobs,
        }
    summary_path = write_run_summary(getattr(ctx.args, "out_dir", None) or "logs", summary_payload)
    print(f"  Run summary: {summary_path}")

    return run_exit_code(ctx.stop.is_set(), ctx.deadline, ctx.signal_interrupted)
