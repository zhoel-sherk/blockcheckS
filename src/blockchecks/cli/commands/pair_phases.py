"""Pair-command helpers: DNS, preflight, matrix load, resume checkpoint, runner."""

from __future__ import annotations

import asyncio
import glob
import logging
import os
import signal
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

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
from blockchecks.engine.triage import disable_ech_from
from blockchecks.terminal import CYAN, GREEN, RED, RESET, YELLOW

log = logging.getLogger(__name__)


STANDARD_TCP_SOURCES = ("standard", "fake", "hostfake", "faked", "fake_multi", "fake_faked")
RESUME_FINGERPRINT_MISMATCH = 4


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
        log.error("%s", f"  {RED}ERROR: {e}{RESET}")
        return preset_domains, 1
    except FileNotFoundError:
        log.info("%s", f"  {YELLOW}Preset '{preset_name}' not found. Available:{RESET}")
        for f in sorted(glob.glob(os.path.join(PROJECT_DIR, "presets/domains", "*.txt"))):
            if os.path.basename(f) in RESERVED_DOMAIN_FILES:
                continue
            log.info("%s", f"    {os.path.basename(f).replace('.txt', '')}")
        return preset_domains, 1

    preset_domains = loaded.domains
    log.info("%s", f"  {CYAN}Preset '{preset_name}': {len(preset_domains)} domains{RESET}")
    if loaded.skipped:
        log.info("%s", f"  {YELLOW}{format_skip_summary(loaded.skipped)}{RESET}")
    if not preset_domains:
        log.error(
            "%s", f"  {RED}ERROR: preset empty after denylist (use --allow-unsafe-domains){RESET}"
        )
        return preset_domains, 1
    auto_enable_gv_ggc(preset_domains)
    return preset_domains, None


def validate_pair_domain(args, preset_domains: list[str]) -> int | None:
    """Ensure a test domain is available; return exit code on error."""
    if not args.domain and not preset_domains:
        log.error("%s", f"{RED}ERROR: --domain or --preset required{RESET}")
        return 1
    if not args.domain and preset_domains:
        args.domain = preset_domains[0]
    return None


@dataclass
class DnsPreflightResult:
    dns_cache: Any
    dns_audits: list
    exit_code: int | None = None
    triage: Any = None


def _default_pin_path() -> str:
    """data_block provider hosts file — default IP pin source.

    Auto-pin probes cached domains with the known-good fake strategy and
    writes back only changed IPs, so this hosts file stays the single
    source for both blockcheckS and a hand-copied Windows hosts.
    """
    try:
        from blockchecks.data_block.provider import get_provider_dir

        return str(get_provider_dir() / "hosts")
    except Exception as exc:
        log.warning("%s", f"  WARNING: provider hosts path unavailable ({exc})")
        return ""


def _resolve_pin_path(args) -> str:
    """Explicit --fixed-ip / env, else the provider hosts file."""
    return (
        getattr(args, "fixed_ip", None)
        or os.environ.get("BLOCKCHECKS_FIXED_IP", "")
        or _default_pin_path()
    )


async def prepare_dns_and_preflight(
    args, preset_domains: list[str], store: Any = None
) -> DnsPreflightResult:
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

    # Load hosts file (--fixed-ip, else provider hosts) into the
    # cache; pinned IPs override DoH order so per-IP throttling cannot
    # flip the result.
    pins = {}
    pin_path = _resolve_pin_path(args)
    if pin_path:
        from blockchecks.checkers.ip_pin import load_pins

        pins = load_pins(pin_path)
        if pins:
            log.info(
                "%s",
                f"  {CYAN}[dns] pinned IPs from {pin_path}: "
                f"{', '.join(f'{d}={ip}' for d, ip in pins.items())}{RESET}",
            )
        if dns_cache is not None:
            dns_cache.set_pins(pins)

    test_domains = list(
        dict.fromkeys((preset_domains or []) + ([args.domain] if args.domain else []))
    )
    from blockchecks.engine.preflight import run_preflight_async

    preflight = await run_preflight_async(
        test_domains,
        PreflightOptions.from_args(
            args, dns_cache=dns_cache, store=store, dns_audits=dns_audits
        ),
    )
    if preflight.exit_code:
        log.error("%s", f"{RED}ERROR: preflight failed: {preflight.error}{RESET}")
        return DnsPreflightResult(dns_cache, dns_audits, exit_code=preflight.exit_code)
    from blockchecks.engine.triage import TriageProfile

    t = preflight.triage if isinstance(preflight.triage, TriageProfile) else None
    args.triage = t
    if args.domain and args.domain in preflight.skip_domains and not getattr(args, "force", False):
        log.info(
            "%s", f"{YELLOW}Prolog: {args.domain} works without bypass — nothing to test{RESET}"
        )
        log.info("%s", f"{YELLOW}Use --force to run strategy matrix anyway{RESET}")
        return DnsPreflightResult(dns_cache, dns_audits, exit_code=0, triage=t)
    return DnsPreflightResult(dns_cache, dns_audits, triage=t)


def build_pair_runner(args, db, dns_cache, dns_audits, pool_size: int) -> AsyncTestRunner:
    """Construct AsyncTestRunner with probe repeat settings from args."""
    secure_dns = SECURE_DNS_DEFAULT and not getattr(args, "no_secure_dns", False)
    repeats, parallel_repeats, repeats_mode, quick_break = repeats_from_args(args)
    lua_extra = list(getattr(args, "lua_extra", None) or [])
    try:
        from blockchecks.engine.blob_filter import lua_files_for_triage
        from blockchecks.engine.config import LUA_CUSTOM_DIR

        lua_extra = list(
            dict.fromkeys(
                lua_extra
                + [
                    os.path.join(LUA_CUSTOM_DIR, n)
                    for n in lua_files_for_triage(getattr(args, "triage", None))
                ]
            )
        )
    except Exception as exc:
        log.warning("%s", f"  WARNING: triage lua extra skipped ({exc})")
    return AsyncTestRunner(
        pool_size=pool_size,
        db=db,
        disable_ech=disable_ech_from(args, getattr(args, "triage", None)),
        secure_dns=secure_dns,
        dns_cache=dns_cache,
        dns_audit={r.domain: r for r in dns_audits},
        pinned_path=_resolve_pin_path(args),
        auto_pin=not bool(getattr(args, "no_auto_pin", False)),
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
) -> Callable[[], None]:
    """Register SIGINT/SIGTERM handlers using StopHandlerState; return restore."""

    def _request_stop():
        state.request_stop(deadline, stop_event)

    def _toggle_debug():
        from blockchecks.engine.log import toggle_debug_mode

        toggle_debug_mode()

    handlers = (
        (signal.SIGINT, _request_stop),
        (signal.SIGTERM, _request_stop),
        (signal.SIGUSR1, _toggle_debug),
    )
    loop_bound = False
    previous: dict[int, Any] = {}

    def restore() -> None:
        if loop_bound:
            for sig, _fn in handlers:
                try:
                    loop.remove_signal_handler(sig)
                except (NotImplementedError, RuntimeError, OSError):
                    pass
            return
        for sig, old in previous.items():
            try:
                signal.signal(sig, old)
            except (ValueError, OSError):
                pass

    try:
        for sig, fn in handlers:
            loop.add_signal_handler(sig, fn)
        loop_bound = True
    except (NotImplementedError, RuntimeError):
        for sig, fn in handlers:
            try:
                previous[sig] = signal.signal(sig, lambda *_a, _f=fn: _f())
            except (AttributeError, OSError, ValueError):
                pass
    return restore


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
        log.info("%s", f"{RED}{mutex_err}{RESET}")
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
        log.info(
            "%s",
            f"\n  {CYAN}DNS-alive discovering {count} voice endpoints "
            f"(DNS + Maks-gaming + STUN)...{RESET}",
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
                    log.info(
                        "%s",
                        f"  {GREEN}  {ep['ip']}:{ep['port']} "
                        f"({ep.get('hostname', '')}) "
                        f"[{src} {method} {ms}ms]{RESET}",
                    )
                if len(multi_eps) > 3:
                    log.info("%s", f"  {GREEN}  ... and {len(multi_eps) - 3} more{RESET}")
                voice_ip = multi_eps[0]["ip"]
                voice_port = multi_eps[0]["port"]
                boot = "on" if multi_eps[0].get("bootstrap") else "off"
                log.info(
                    "%s",
                    f"  {GREEN}Voice source: dns-alive "
                    f"({len(multi_eps)}/{count}) {voice_ip}:{voice_port} "
                    f"method={multi_eps[0].get('method', '?')} "
                    f"bootstrap={boot}{RESET}",
                )
            else:
                log.info(
                    "%s",
                    f"  {YELLOW}No alive endpoints — using static DEFAULT_VOICE_* "
                    f"(try --auto-discover / VPN if needed){RESET}",
                )
                voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
        except Exception as e:
            log.error("%s", f"  {YELLOW}discover-dns error: {e}{RESET}")
            voice_ip, voice_port = DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT
    elif not explicit_ip and auto_count is not None:
        count = auto_count
        log.info("%s", f"\n  {CYAN}Auto-discovering {count} voice endpoints...{RESET}")
        try:
            from blockchecks.checkers.voice_discovery import discover_multiple

            multi_eps = await discover_multiple(count, use_dns=True)
            if multi_eps:
                for ep in multi_eps[:3]:
                    log.info("%s", f"  {GREEN}  {ep['ip']}:{ep['port']} ({ep['hostname']}){RESET}")
                if len(multi_eps) > 3:
                    log.info("%s", f"  {GREEN}  ... and {len(multi_eps) - 3} more{RESET}")
                voice_ip = multi_eps[0]["ip"]
                voice_port = multi_eps[0]["port"]
            else:
                log.info("%s", f"  {YELLOW}No endpoints found — using static{RESET}")
        except Exception as e:
            log.error("%s", f"  {YELLOW}Discovery error: {e}{RESET}")

    if args.full_voice and not has_token:
        from blockchecks.checkers.voice_discovery import discord_settings_hint

        log.info("%s", f"  {YELLOW}No Discord token. --full-voice → STUN only{RESET}")
        log.info("%s", f"  Add token to {discord_settings_hint()}")

    if full_voice:
        log.info("%s", f"  {CYAN}Full-voice mode: gateway WS → OP2 Ready → UDP endpoint{RESET}")

    return VoiceContext(
        voice_ip=voice_ip,
        voice_port=voice_port,
        full_voice=full_voice,
        has_token=has_token,
        multi_eps=multi_eps,
    ), None


async def _resume_generate_triage(args, db):
    """Triage prune changes the item list; resume must keep the original matrix."""
    if not getattr(args, "resume", False) or db is None:
        return getattr(args, "triage", None)
    latest = getattr(db, "latest_checkpoint", None)
    if callable(latest) and await latest():
        return None
    keys_fn = getattr(db, "get_completed_tcp_keys", None)
    if callable(keys_fn) and await keys_fn():
        return None
    return getattr(args, "triage", None)


async def load_strategy_items(args, db) -> StrategyLoadResult:
    """Load or generate TCP/UDP strategy items."""
    strategy_preset = getattr(args, "strategy_preset", None)
    if strategy_preset:
        from blockchecks.cli.presets import PresetPathError, resolve_strategy_preset

        try:
            sp_path = resolve_strategy_preset(strategy_preset)
        except PresetPathError as e:
            log.error("%s", f"  {RED}ERROR: {e}{RESET}")
            return StrategyLoadResult([], [], [], set(), error_code=1)
        except FileNotFoundError:
            log.error("%s", f"  {RED}ERROR: strategy preset '{strategy_preset}' not found{RESET}")
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
        udp_src = getattr(args, "udp_sources", "") or "custom,standard_udp"
        if getattr(args, "tcp_only", False):
            udp_src = ""
        tcp_sources = [s for s in tcp_src.split(",") if s]
        udp_sources = [s for s in udp_src.split(",") if s]
        tcp_sources_list = tcp_sources
        gen_triage = await _resume_generate_triage(args, db)

        log.info("%s", f"\n  {CYAN}Generating strategies...{RESET}")
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
                triage=gen_triage,
            )
        if not udp_items and udp_sources and not args.tcp_only:
            udp_items = await scanner.generate_udp(
                sources=udp_sources,
                domain=args.domain,
                scan_level=args.scan_level,
                max_count=max(1, args.max // 2) if args.max >= 2 else 50,
                state_db=db,
                user_matrix=user_matrix,
                triage=gen_triage,
            )
        log.info("%s", f"  Generated: {len(tcp_items)} TCP + {len(udp_items)} UDP strategies")
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

    log.info(
        "%s", f"\n  {CYAN}blockcheckS — {'Pair Matrix' if not args.tcp_only else 'TCP Scan'}{RESET}"
    )
    log.info(
        "%s",
        f"  Domain:     {', '.join(domains_to_test[:5])}{'...' if len(domains_to_test) > 5 else ''}",
    )
    log.info("%s", f"  TCP:        {len(tcp_items)} strategies")
    log.info("%s", f"  UDP:        {len(udp_items)} strategies")
    log.info("%s", f"  Voice:      {voice_ip}:{voice_port}")
    if not tcp_items:
        log.error("  ERROR: no strategies loaded")
        return 1
    log.info("%s", f"  Full Voice: {'discovery+STUN' if full_voice else 'STUN only'}")
    log.info("%s", f"  UDP Bypass: {'yes' if args.udp_bypass else 'no'}")
    log.info("%s", f"  Workers:    {pool_size}")
    log.info("%s", f"  DB:         {args.db}")
    return None


async def resolve_resume_checkpoint(args, db, fp: str) -> tuple[Any | None, int | None]:
    """Load resume checkpoint; fingerprint mismatch returns RESUME_FINGERPRINT_MISMATCH."""
    resume_from = None
    if args.resume:
        resume_from = await db.latest_checkpoint()
        if resume_from:
            if fingerprint_mismatch(resume_from.fingerprint, fp):
                log.error(
                    "%s", f"  {RED}ERROR: matrix changed, refuse --resume; start fresh{RESET}"
                )
                log.info("%s", f"  checkpoint fp={resume_from.fingerprint} current fp={fp}")
                return None, RESUME_FINGERPRINT_MISMATCH
            log.info(
                "%s",
                f"  {YELLOW}Resuming after {resume_from.tcp_label}+{resume_from.udp_label}{RESET}",
            )
        else:
            log.info("%s", f"  {YELLOW}No checkpoint found — starting fresh{RESET}")
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
        log.info(
            "%s",
            f"  {YELLOW}Multi-EP fan-out: {len(targets)} endpoints × pairs "
            f"(~{n_pairs} probes){RESET}",
        )
    all_pairs: list = []
    for ip, port in targets:
        log_dom = pair_log_domain(domain, ip, port, multi=multi)
        if multi:
            log.info(
                "%s", f"\n  {CYAN}[UDP Pairs]{RESET} ep={ip}:{port}  {len(udp_items)} strategies..."
            )
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


async def _seed_quarantine_from_db(db, quarantine, queue, qcfg) -> None:
    """Pre-seed quarantine from campaign DB and re-sync AQ hard exclusions."""
    if qcfg is None or db is None or quarantine is None:
        return
    try:
        rows = await db.domain_pass_rows()
        seeded = quarantine.seed_from_rows(rows)
        if hasattr(queue, "excluded_domains"):
            queue.excluded_domains |= quarantine.exclude_domains()
        if seeded:
            log.warning(
                "%s",
                f"  [quarantine] pre-seeded {len(seeded)} dead domains from DB "
                f"(0 PASS in >= {qcfg.min_attempts} attempts): "
                f"{', '.join(sorted(seeded))}",
            )
            for dom in seeded:
                info = quarantine.quarantined.get(dom) or {}
                try:
                    await db.quarantine_domain(
                        dom,
                        reason=info.get("reason", ""),
                        failed=info.get("attempts", 0),
                    )
                except Exception as exc:
                    log.warning(
                        "%s", f"  [quarantine] DB persist skipped for {dom} ({exc})"
                    )
                    break
    except Exception as exc:
        log.warning("%s", f"  [quarantine] seed skipped ({exc})")


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
    backend = resolve_probe_backend(args)
    log.info(
        "%s",
        f"  {GREEN}Adaptive queue:{RESET} ε={eps}, backend={backend}"
        + (f", curl-parallel={curl_parallel}" if curl_parallel > 1 else ""),
    )

    async def _resume_job(job):
        return (job.item.label, job.domain) in completed_tcp

    completed_tcp: set[tuple[str, str]] = set()
    if getattr(args, "resume", False):
        reprobe = getattr(args, "reprobe_failed", 0)
        reprobe_failed = 0 if reprobe is None else int(reprobe)
        completed_tcp = await db.get_resume_skip_tcp_keys(reprobe_failed=reprobe_failed)

    from blockchecks.engine.domain_quarantine import DomainQuarantine, quarantine_from_args

    quarantine = None
    qcfg = quarantine_from_args(args)
    if qcfg is not None:
        quarantine = DomainQuarantine(qcfg)

    queue, skipped = await build_adaptive_queue(
        tcp_items,
        domains_to_test,
        db,
        epsilon=getattr(args, "adaptive_epsilon", 0.1),
        load_weights=not getattr(args, "no_adaptive_weights", False),
        resume_check=_resume_job if getattr(args, "resume", False) else None,
        triage=getattr(args, "triage", None),
        quarantine=quarantine,
    )
    await _seed_quarantine_from_db(db, quarantine, queue, qcfg)
    log.info("%s", f"  AQ pending jobs: {len(queue)} (+{skipped} resume skip)")
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
        quarantine=quarantine,
    )
    tcp_passed = aq_result.passed
    primary = domains_to_test[0]
    log.info(
        "%s",
        f"\n  TCP {primary}: {GREEN}{tcp_passed}{RESET}/{aq_result.done} passed",
    )
    if not getattr(args, "no_adaptive_weights", False):
        await persist_adaptive_weights(db, aq_result.weights)
    m = aq_result.metrics
    if m.time_to_first_pass is not None:
        log.info(
            "%s",
            f"  AQ first PASS: {m.time_to_first_pass:.1f}s  fan-out enqueued: {m.fanout_enqueued}",
        )

    pairs: list = []
    if not args.tcp_only and udp_items and not stop_event.is_set():
        details = await db.get_working_tcp_details(primary)
        by_label = {i.label: i for i in tcp_items}
        tcp_results = tcp_results_from_details(by_label, details, primary)
        if tcp_results:
            log.info("%s", f"\n  {CYAN}[UDP Pairs]{RESET} {len(udp_items)} strategies...")
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
            log.info("%s", f"  {YELLOW}No working TCP for pairs after AQ{RESET}")

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

    completed_tcp: set[tuple[str, str]] = set()
    if getattr(args, "resume", False):
        db = getattr(runner, "db", None)
        get_keys = getattr(db, "get_resume_skip_tcp_keys", None) if db is not None else None
        if asyncio.iscoroutinefunction(get_keys):
            reprobe = getattr(args, "reprobe_failed", 0)
            reprobe_failed = 0 if reprobe is None else int(reprobe)
            completed_tcp = await get_keys(reprobe_failed=reprobe_failed)

    async def _resume_done(label: str, dom: str) -> bool:
        return (label, dom) in completed_tcp

    resume_check = _resume_done if completed_tcp else None

    for domain in domains_to_test:
        if stop_event.is_set():
            break
        pending_count = sum(1 for i in tcp_items if (i.label, domain) not in completed_tcp)
        resume_skip = len(tcp_items) - pending_count
        log.info(
            "%s",
            f"\n  {CYAN}[TCP Phase]{RESET} {domain}: {pending_count} strategies"
            + (f" (+{resume_skip} resume skip)" if resume_skip else ""),
        )
        if use_family_gates:
            tcp_results, _, _, _ = await run_tcp_with_family_gates(
                runner,
                tcp_items,
                domain,
                scan_level=scan_level,
                timeout=args.timeout,
                stop_event=stop_event,
                resume_check=resume_check,
            )
        else:
            pending_items = [i for i in tcp_items if (i.label, domain) not in completed_tcp]
            if pending_items:
                tcp_results = await runner.test_batch_tcp(pending_items, domain, args.timeout)
            else:
                tcp_results = []
        all_tcp_results.extend(tcp_results)
        domain_passed = sum(1 for r in tcp_results if r.success)
        tcp_passed += domain_passed
        log.info("%s", f"\n  TCP {domain}: {GREEN}{domain_passed}{RESET}/{len(tcp_results)} passed")

        for r in tcp_results:
            if r.success:
                run_set.add(r.item.label)

        if not args.tcp_only and udp_items and domain == domains_to_test[0]:
            if stop_event.is_set():
                break
            log.info("%s", f"\n  {CYAN}[UDP Pairs]{RESET} {len(udp_items)} strategies...")
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
            log.info("%s", f"\n  {CYAN}Export configs...{RESET}")
            log.info("%s", f"  {GREEN}{export_result['keenetic']}{RESET}")
            log.info("%s", f"  {GREEN}{export_result['raw']}{RESET}")
            log.info("%s", f"  {GREEN}{export_result['user_list']}{RESET}")

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
    write_run_summary(getattr(args, "out_dir", None) or "", summary_payload)

    if tcp_passed <= 0:
        return 1
    if pairs and not any(p.overall == "PASS" for p in pairs) and not args.tcp_only:
        return 1
    return run_exit_code(stop_event.is_set(), deadline, stop_state.signal_interrupted)
