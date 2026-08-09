"""Pair command phase helpers — extracted from cmd_pair for C901."""

from __future__ import annotations

import asyncio
import glob
import os
import signal
from dataclasses import dataclass, field
from typing import Any

from colorama import Fore, Style

from blockchecks.checkers.curl_probe import repeats_from_args
from blockchecks.checkers.dns_secure import prepare_dns_for_run
from blockchecks.checkers.voice_dns import pair_log_domain, resolve_voice_targets
from blockchecks.engine.adaptive_runner import (
    build_adaptive_queue,
    persist_adaptive_weights,
    run_adaptive_tcp,
)
from blockchecks.engine.async_runner import AsyncTestRunner, tcp_results_from_details
from blockchecks.engine.config import (
    CONFIGS_DIR,
    DEFAULT_VOICE_IP,
    DEFAULT_VOICE_PORT,
    DPI_TESTER_SETTINGS,
    PROJECT_DIR,
    SECURE_DNS_DEFAULT,
    resolve_probe_backend,
)
from blockchecks.engine.domain_loader import (
    RESERVED_DOMAIN_FILES,
    auto_enable_gv_ggc,
    format_skip_summary,
    load_preset,
)
from blockchecks.engine.family_needs import run_tcp_with_family_gates
from blockchecks.engine.matrix_generator import MatrixGenerator, StrategyItem
from blockchecks.engine.preflight import PreflightOptions
from blockchecks.engine.run_deadline import RunDeadline
from blockchecks.engine.run_finalize import (
    maybe_export_configs,
    run_exit_code,
    write_run_summary,
)
from blockchecks.engine.store import fingerprint_mismatch
from blockchecks.engine.strategy_loader import StrategyLoader

CYAN = Fore.CYAN
GREEN = Fore.GREEN + Style.BRIGHT
RED = Fore.RED + Style.BRIGHT
YELLOW = Fore.YELLOW
RESET = Style.RESET_ALL

STANDARD_TCP_SOURCES = ("standard", "fake", "hostfake", "faked", "fake_multi", "fake_faked")


@dataclass
class VoiceContext:
    voice_ip: str
    voice_port: int
    full_voice: bool
    has_token: bool
    multi_eps: list = field(default_factory=list)


@dataclass
class StrategyLoadResult:
    tcp_items: list[StrategyItem]
    udp_items: list[StrategyItem]
    tcp_sources_list: list[str]
    run_set: set
    error_code: int | None = None


@dataclass
class PhaseResult:
    all_tcp_results: list
    pairs: list
    tcp_passed: int
    aq_result: Any | None = None


def resolve_preset_domains(args) -> tuple[list[str], int | None]:
    """Load preset domains; return (domains, exit_code) with exit_code set on error."""
    preset_domains: list[str] = []
    preset_name = getattr(args, "preset", None)
    if not preset_name:
        return preset_domains, None

    from blockchecks.cli.presets import PresetPathError

    try:
        loaded = load_preset(
            preset_name,
            allow_unsafe=getattr(args, "allow_unsafe_domains", False),
        )
    except PresetPathError as e:
        print(f"  {Fore.RED}ERROR: {e}{RESET}")
        return preset_domains, 1
    except FileNotFoundError:
        print(f"  {Fore.YELLOW}Preset '{preset_name}' not found. Available:{RESET}")
        for f in sorted(glob.glob(os.path.join(PROJECT_DIR, "presets/domains", "*.txt"))):
            if os.path.basename(f) in RESERVED_DOMAIN_FILES:
                continue
            print(f"    {os.path.basename(f).replace('.txt', '')}")
        return preset_domains, 1

    preset_domains = loaded.domains
    print(f"  {Fore.CYAN}Preset '{preset_name}': {len(preset_domains)} domains{RESET}")
    if loaded.skipped:
        print(f"  {YELLOW}{format_skip_summary(loaded.skipped)}{RESET}")
    if not preset_domains:
        print(f"  {Fore.RED}ERROR: preset empty after denylist (use --allow-unsafe-domains){RESET}")
        return preset_domains, 1
    auto_enable_gv_ggc(preset_domains)
    return preset_domains, None


def validate_pair_domain(args, preset_domains: list[str]) -> int | None:
    """Ensure a test domain is available; return exit code on error."""
    if not args.domain and not preset_domains:
        print(f"{Fore.RED}ERROR: --domain or --preset required{RESET}")
        return 1
    if not args.domain and preset_domains:
        args.domain = preset_domains[0]
    return None


@dataclass
class DnsPreflightResult:
    dns_cache: Any
    dns_audits: list
    exit_code: int | None = None


async def prepare_dns_and_preflight(args, preset_domains: list[str]) -> DnsPreflightResult:
    """DNS + preflight; exit_code set on failure or prolog skip."""
    domains_for_dns = list(
        dict.fromkeys((preset_domains or []) + ([args.domain] if args.domain else []))
    )
    auto_enable_gv_ggc(domains_for_dns)
    from blockchecks.data_block.provider import provider_name

    provider_name(allow_detect=True)
    secure_dns = SECURE_DNS_DEFAULT and not getattr(args, "no_secure_dns", False)
    dns_cache, dns_audits, dns_rc = prepare_dns_for_run(
        domains_for_dns,
        secure_dns=secure_dns,
        skip_audit=getattr(args, "skip_dns_audit", False),
        allow_hijack=getattr(args, "allow_dns_hijack", False),
        doh_server=getattr(args, "doh_server", None) or None,
    )
    if dns_rc:
        return DnsPreflightResult(dns_cache, dns_audits, exit_code=dns_rc)

    test_domains = list(
        dict.fromkeys((preset_domains or []) + ([args.domain] if args.domain else []))
    )
    from blockchecks.engine.preflight import run_preflight_async

    preflight = await run_preflight_async(
        test_domains,
        PreflightOptions.from_args(args, dns_cache=dns_cache, store=None),
    )
    if preflight.exit_code:
        print(f"{Fore.RED}ERROR: preflight failed: {preflight.error}{RESET}")
        return DnsPreflightResult(dns_cache, dns_audits, exit_code=preflight.exit_code)
    if args.domain and args.domain in preflight.skip_domains and not getattr(args, "force", False):
        print(f"{YELLOW}Prolog: {args.domain} works without bypass — nothing to test{RESET}")
        print(f"{YELLOW}Use --force to run strategy matrix anyway{RESET}")
        return DnsPreflightResult(dns_cache, dns_audits, exit_code=0)
    return DnsPreflightResult(dns_cache, dns_audits)


def build_pair_runner(args, db, dns_cache, dns_audits, pool_size: int) -> AsyncTestRunner:
    """Construct AsyncTestRunner with probe repeat settings from args."""
    secure_dns = SECURE_DNS_DEFAULT and not getattr(args, "no_secure_dns", False)
    repeats, parallel_repeats, repeats_mode, quick_break = repeats_from_args(args)
    lua_extra = list(getattr(args, "lua_extra", None) or [])
    return AsyncTestRunner(
        pool_size=pool_size,
        db=db,
        disable_ech=bool(getattr(args, "disable_ech", False)),
        secure_dns=secure_dns,
        dns_cache=dns_cache,
        dns_audit={r.domain: r for r in dns_audits},
        repeats=repeats,
        parallel_repeats=parallel_repeats,
        repeats_mode=repeats_mode,
        quick_break=quick_break,
        try_wssize=not getattr(args, "no_wssize", False)
        and getattr(args, "protocol", "tls12") == "tls12",
        lua_bridge=resolve_probe_backend(args) == "lua_bridge",
        bridge_batch=int(getattr(args, "bridge_batch", 500) or 500),
        lua_bridge_compare=bool(getattr(args, "lua_bridge_compare", False)),
        lua_extra=lua_extra,
    )


@dataclass
class StopHandlerState:
    signal_interrupted: bool = False

    def request_stop(self, deadline: RunDeadline | None, stop_event: asyncio.Event) -> None:
        self.signal_interrupted = True
        if deadline and not deadline.triggered:
            deadline.reason = "signal"
        stop_event.set()


def register_stop_handlers(
    loop: asyncio.AbstractEventLoop,
    state: StopHandlerState,
    deadline: RunDeadline | None,
    stop_event: asyncio.Event,
) -> None:
    """Register SIGINT/SIGTERM handlers using StopHandlerState."""

    def _request_stop():
        state.request_stop(deadline, stop_event)

    def _toggle_debug():
        currently = os.environ.get("BLOCKCHECKS_NFQWS2_DEBUG", "").strip()
        if currently in ("1", "true", "on", "yes"):
            os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)
            print("  [debug] SIGUSR1 — nfqws2 --debug OFF on next restart", flush=True)
        else:
            os.environ["BLOCKCHECKS_NFQWS2_DEBUG"] = "1"
            print("  [debug] SIGUSR1 — nfqws2 --debug ON on next restart", flush=True)

    try:
        loop.add_signal_handler(signal.SIGINT, _request_stop)
        loop.add_signal_handler(signal.SIGTERM, _request_stop)
        loop.add_signal_handler(signal.SIGUSR1, _toggle_debug)
    except (NotImplementedError, RuntimeError):
        signal.signal(signal.SIGINT, lambda *_: _request_stop())
        signal.signal(signal.SIGTERM, lambda *_: _request_stop())
        try:
            signal.signal(signal.SIGUSR1, lambda *_: _toggle_debug())
        except (AttributeError, OSError):
            pass


async def discover_voice_endpoints(args) -> tuple[VoiceContext | None, int | None]:
    """Discover voice IP/port; return (context, exit_code) — exit_code 1 on mutex error."""
    voice_ip = getattr(args, "ip", None) or DEFAULT_VOICE_IP
    voice_port = getattr(args, "port", None) or DEFAULT_VOICE_PORT

    from blockchecks.checkers.voice_discovery import load_token
    from blockchecks.checkers.voice_dns import (
        check_discover_mutex,
        discover_dns_alive,
        positive_discover_count,
    )

    mutex_err = check_discover_mutex(
        getattr(args, "discover_dns", None),
        getattr(args, "auto_discover", None),
    )
    if mutex_err:
        print(f"{Fore.RED}{mutex_err}{RESET}")
        return None, 1

    token = load_token()
    has_token = bool(token)
    full_voice = args.full_voice and has_token

    explicit_ip = voice_ip != DEFAULT_VOICE_IP
    discover_dns = getattr(args, "discover_dns", None)
    auto_discover = getattr(args, "auto_discover", None)
    multi_eps: list = []

    dns_count = positive_discover_count(discover_dns)
    auto_count = positive_discover_count(auto_discover)

    if not explicit_ip and dns_count is not None:
        count = dns_count
        print(
            f"\n  {CYAN}DNS-alive discovering {count} voice endpoints "
            f"(DNS + Maks-gaming + STUN)...{RESET}"
        )
        try:
            multi_eps = await discover_dns_alive(
                count,
                use_bootstrap=not getattr(args, "discover_dns_no_bootstrap", False),
                region=getattr(args, "voice_region", None) or "finland",
                try_burst=bool(getattr(args, "voice_burst", False)),
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
    elif not explicit_ip and auto_count is not None:
        count = auto_count
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
        print(f"  {CYAN}Full-voice mode: gateway WS → OP2 Ready → UDP endpoint{RESET}")

    return VoiceContext(
        voice_ip=voice_ip,
        voice_port=voice_port,
        full_voice=full_voice,
        has_token=has_token,
        multi_eps=multi_eps,
    ), None


async def load_strategy_items(args, db) -> StrategyLoadResult:
    """Load or generate TCP/UDP strategy items."""
    strategy_preset = getattr(args, "strategy_preset", None)
    if strategy_preset:
        from blockchecks.cli.presets import PresetPathError, resolve_strategy_preset

        try:
            sp_path = resolve_strategy_preset(strategy_preset)
        except PresetPathError as e:
            print(f"  {Fore.RED}ERROR: {e}{RESET}")
            return StrategyLoadResult([], [], [], set(), error_code=1)
        except FileNotFoundError:
            print(f"  {Fore.RED}ERROR: strategy preset '{strategy_preset}' not found{RESET}")
            return StrategyLoadResult([], [], [], set(), error_code=1)
        args.user_matrix = str(sp_path)

    do_generate = getattr(args, "generate", False)
    user_matrix = getattr(args, "user_matrix", "") or ""
    run_set: set = set()
    tcp_items: list[StrategyItem] = []
    udp_items: list[StrategyItem] = []
    tcp_sources_list: list[str] = []

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
        tcp_sources_list = tcp_sources

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
            StrategyItem(label=os.path.basename(c).replace(".conf", ""), strategy=c, is_config=True)
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

    return StrategyLoadResult(
        tcp_items=tcp_items,
        udp_items=udp_items,
        tcp_sources_list=tcp_sources_list,
        run_set=run_set,
    )


def print_pair_banner(
    args,
    preset_domains: list[str],
    tcp_items: list[StrategyItem],
    udp_items: list[StrategyItem],
    voice_ip: str,
    voice_port: int,
    full_voice: bool,
    pool_size: int,
) -> int | None:
    """Print run header; return 1 if no TCP strategies."""
    domains_to_test = preset_domains if preset_domains else [args.domain]

    print(f"\n  {CYAN}blockcheckS — {'Pair Matrix' if not args.tcp_only else 'TCP Scan'}{RESET}")
    print(
        f"  Domain:     {', '.join(domains_to_test[:5])}{'...' if len(domains_to_test) > 5 else ''}"
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
    return None


async def resolve_resume_checkpoint(args, db, fp: str) -> tuple[Any | None, int | None]:
    """Load resume checkpoint; return (resume_from, exit_code) on fingerprint mismatch."""
    resume_from = None
    if args.resume:
        resume_from = await db.latest_checkpoint()
        if resume_from:
            if fingerprint_mismatch(resume_from.fingerprint, fp):
                print(f"  {RED}ERROR: matrix changed, refuse --resume; start fresh{RESET}")
                print(f"  checkpoint fp={resume_from.fingerprint} current fp={fp}")
                return None, 1
            print(
                f"  {YELLOW}Resuming after {resume_from.tcp_label}+{resume_from.udp_label}{RESET}"
            )
        else:
            print(f"  {YELLOW}No checkpoint found — starting fresh{RESET}")
    return resume_from, None


async def _run_pair_matrix_multi_ep(
    runner: AsyncTestRunner,
    tcp_results: list,
    udp_items: list[StrategyItem],
    domain: str,
    voice_ip: str,
    voice_port: int,
    multi_eps: list,
    *,
    udp_timeout: float,
    udp_bypass: bool,
    resume_from: Any,
    full_voice: bool,
    fingerprint: str,
) -> list:
    """Fan-out pair matrix across discovered voice endpoints (V2-1)."""
    targets = resolve_voice_targets(voice_ip, voice_port, multi_eps)
    multi = len(targets) > 1
    if multi:
        n_pairs = len([r for r in tcp_results if r.success]) * len(udp_items) * len(targets)
        print(
            f"  {YELLOW}Multi-EP fan-out: {len(targets)} endpoints × pairs "
            f"(~{n_pairs} probes){RESET}"
        )
    all_pairs: list = []
    for ip, port in targets:
        log_dom = pair_log_domain(domain, ip, port, multi=multi)
        if multi:
            print(f"\n  {CYAN}[UDP Pairs]{RESET} ep={ip}:{port}  {len(udp_items)} strategies...")
        batch = await runner.test_pair_matrix(
            tcp_results,
            udp_items,
            domain,
            ip,
            port,
            udp_timeout=udp_timeout,
            udp_bypass=udp_bypass,
            resume_from=resume_from,
            full_voice=full_voice,
            fingerprint=fingerprint,
            pair_domain=log_dom if multi else None,
        )
        all_pairs.extend(batch)
    return all_pairs


async def run_adaptive_pair_phase(
    args,
    runner: AsyncTestRunner,
    db,
    tcp_items: list[StrategyItem],
    udp_items: list[StrategyItem],
    domains_to_test: list[str],
    voice_ip: str,
    voice_port: int,
    full_voice: bool,
    resume_from: Any,
    fp: str,
    stop_event: asyncio.Event,
    curl_parallel: int,
    protocol: str,
    multi_eps: list | None = None,
) -> PhaseResult:
    """Adaptive TCP queue phase with optional UDP pair matrix."""
    eps = getattr(args, "adaptive_epsilon", 0.1)
    print(
        f"  {GREEN}Adaptive queue:{RESET} ε={eps}"
        + (f", curl-parallel={curl_parallel}" if curl_parallel > 1 else "")
    )

    async def _resume_job(job):
        return bool(args.resume and await db.has_tcp_result(job.item.label, job.domain))

    queue, skipped = await build_adaptive_queue(
        tcp_items,
        domains_to_test,
        db,
        epsilon=getattr(args, "adaptive_epsilon", 0.1),
        load_weights=not getattr(args, "no_adaptive_weights", False),
        resume_check=_resume_job if args.resume else None,
    )
    print(f"  AQ pending jobs: {len(queue)} (+{skipped} resume skip)")
    aq_result = await run_adaptive_tcp(
        runner,
        queue,
        timeout=args.timeout,
        curl_parallel=curl_parallel,
        protocol=protocol,
        stop_event=stop_event,
        lua_bridge=resolve_probe_backend(args) == "lua_bridge",
        bridge_batch=int(getattr(args, "bridge_batch", 500) or 500),
        workers=max(1, int(getattr(args, "parallel", 4) or 4)),
    )
    tcp_passed = aq_result.passed
    if not getattr(args, "no_adaptive_weights", False):
        await persist_adaptive_weights(db, aq_result.weights)
    m = aq_result.metrics
    if m.time_to_first_pass is not None:
        print(
            f"  AQ first PASS: {m.time_to_first_pass:.1f}s  fan-out enqueued: {m.fanout_enqueued}"
        )

    pairs: list = []
    if not args.tcp_only and udp_items and not stop_event.is_set():
        primary = domains_to_test[0]
        details = await db.get_working_tcp_details(primary)
        by_label = {i.label: i for i in tcp_items}
        tcp_results = tcp_results_from_details(by_label, details, primary)
        if tcp_results:
            print(f"\n  {CYAN}[UDP Pairs]{RESET} {len(udp_items)} strategies...")
            pairs = await _run_pair_matrix_multi_ep(
                runner,
                tcp_results,
                udp_items,
                primary,
                voice_ip,
                voice_port,
                multi_eps or [],
                udp_timeout=args.udp_timeout,
                udp_bypass=args.udp_bypass,
                resume_from=resume_from,
                full_voice=full_voice,
                fingerprint=fp,
            )
            AsyncTestRunner.print_matrix(pairs)
        else:
            print(f"  {YELLOW}No working TCP for pairs after AQ{RESET}")

    return PhaseResult([], pairs, tcp_passed, aq_result=aq_result)


async def run_standard_pair_phase(
    args,
    runner: AsyncTestRunner,
    tcp_items: list[StrategyItem],
    udp_items: list[StrategyItem],
    domains_to_test: list[str],
    voice_ip: str,
    voice_port: int,
    full_voice: bool,
    resume_from: Any,
    fp: str,
    stop_event: asyncio.Event,
    scan_level: str,
    use_family_gates: bool,
    run_set: set,
    multi_eps: list | None = None,
) -> PhaseResult:
    """Standard per-domain TCP batch with UDP pair matrix on primary domain."""
    all_tcp_results: list = []
    pairs: list = []
    tcp_passed = 0

    for domain in domains_to_test:
        if stop_event.is_set():
            break
        print(f"\n  {CYAN}[TCP Phase]{RESET} {domain}: {len(tcp_items)} strategies...")
        if use_family_gates:
            tcp_results, _, _, _ = await run_tcp_with_family_gates(
                runner,
                tcp_items,
                domain,
                scan_level=scan_level,
                timeout=args.timeout,
                stop_event=stop_event,
            )
        else:
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
                break
            print(f"\n  {CYAN}[UDP Pairs]{RESET} {len(udp_items)} strategies...")
            pairs = await _run_pair_matrix_multi_ep(
                runner,
                tcp_results,
                udp_items,
                domain,
                voice_ip,
                voice_port,
                multi_eps or [],
                udp_timeout=args.udp_timeout,
                udp_bypass=args.udp_bypass,
                resume_from=resume_from,
                full_voice=full_voice,
                fingerprint=fp,
            )
            AsyncTestRunner.print_matrix(pairs)

    return PhaseResult(all_tcp_results, pairs, tcp_passed)


async def finalize_pair_run(
    args,
    db,
    deadline: RunDeadline | None,
    stop_event: asyncio.Event,
    stop_state: StopHandlerState,
    tcp_passed: int,
    pairs: list,
    aq_result: Any | None,
) -> int:
    """Export configs, write summary, and compute final exit code."""
    from blockchecks.engine.run_finalize import (
        maybe_sync_data_block,
        maybe_write_best_config_data_block,
    )

    await maybe_write_best_config_data_block()
    await maybe_sync_data_block(args)
    export_result = None
    if getattr(args, "out_dir", None):
        export_result = await maybe_export_configs(
            db,
            args,
            primary=args.domain,
            domains_file=None,
            stop_set=stop_event.is_set(),
            deadline=deadline,
        )
        if export_result:
            print(f"\n  {CYAN}Export configs...{RESET}")
            print(f"  {GREEN}{export_result['keenetic']}{RESET}")
            print(f"  {GREEN}{export_result['raw']}{RESET}")
            print(f"  {GREEN}{export_result['user_list']}{RESET}")

    summary_payload = {
        "command": "scan" if getattr(args, "tcp_only", False) else "pair",
        "deadline_sec": deadline.budget_sec if deadline else None,
        "stopped_reason": (
            deadline.reason
            if deadline and deadline.triggered
            else ("signal" if stop_state.signal_interrupted else None)
        ),
        "db_path": args.db,
        "export_paths": export_result,
        "domain": args.domain,
    }
    if aq_result:
        summary_payload["jobs_done"] = aq_result.done
        summary_payload["passed"] = aq_result.passed
    write_run_summary(getattr(args, "out_dir", None) or "logs", summary_payload)

    if tcp_passed <= 0:
        return 1
    if pairs and not any(p.overall == "PASS" for p in pairs) and not args.tcp_only:
        return 1
    return run_exit_code(stop_event.is_set(), deadline, stop_state.signal_interrupted)
