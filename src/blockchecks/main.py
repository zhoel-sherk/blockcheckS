"""bs full — mass strategy×coverage orchestrator + conf export."""

from __future__ import annotations

import argparse
import asyncio
import sys

from colorama import init as colorama_init

from blockchecks.cli.parser import (
    add_adaptive_args,
    add_curl_fanout_args,
    add_curl_repeats_args,
    add_domain_filter_args,
    add_family_gate_args,
    add_lua_bridge_args,
    add_protocol_phase_args,
    add_secure_dns_args,
    add_store_args,
    add_system_deps_args,
    add_time_limit_args,
    ensure_system_deps_or_exit,
)
from blockchecks.engine.config import (
    effective_default_pool_size,
)
from blockchecks.engine.matrix_generator import MatrixGenerator
from blockchecks.engine.run_deadline import validate_time_limit_args
from blockchecks.main_phases import (
    arm_run_deadline,
    arm_stop_handlers,
    build_async_runner,
    build_full_run_context,
    build_matrix_fingerprint,
    cleanup_runner,
    configure_tcp_execution,
    discover_voice_endpoint,
    export_and_summarize,
    generate_strategy_items,
    load_run_domains,
    open_full_run_db,
    prepare_run_dns,
    print_full_run_banner,
    print_optional_phases_skip,
    print_settle_profile,
    resolve_settle_profile,
    run_http_phase,
    run_pairs_phase,
    run_preflight_filter,
    run_quic_phase,
    run_tcp_coverage_phase,
)

colorama_init(autoreset=True)


async def run_full(args) -> int:
    from blockchecks.engine.run_control import run_session

    async with run_session("full", db_path=getattr(args, "db", None)):
        return await _run_full_campaign(args)


async def _run_full_campaign(args) -> int:
    db = await open_full_run_db(args)

    domains, domains_file, domains_rc = load_run_domains(args)
    if domains_rc is not None:
        return domains_rc

    dns_cache, dns_audits, dns_rc = prepare_run_dns(args, domains)
    if dns_rc:
        return dns_rc

    domains, primary, preflight_rc = await run_preflight_filter(
        args, domains, args.domain or domains[0], dns_cache, db
    )
    if preflight_rc is not None:
        return preflight_rc

    ctx = build_full_run_context(args, db, domains, domains_file, dns_cache, dns_audits)
    ctx.primary = primary

    print_full_run_banner(ctx)

    gen = MatrixGenerator()
    gen_rc = await generate_strategy_items(ctx, gen)
    if gen_rc is not None:
        return gen_rc

    configure_tcp_execution(ctx)

    ctx.settle_profile = resolve_settle_profile(args)
    print_settle_profile(ctx.settle_profile)

    ctx.fp = build_matrix_fingerprint(ctx)

    ctx.runner = build_async_runner(ctx)
    arm_stop_handlers(ctx)
    await arm_run_deadline(ctx)

    await ctx.runner.start()
    try:
        await run_tcp_coverage_phase(ctx)

        if ctx.stop.is_set():
            print_optional_phases_skip(ctx)

        await run_http_phase(ctx)
        voice_ip, voice_port = await discover_voice_endpoint(ctx)
        await run_quic_phase(ctx)
        await run_pairs_phase(ctx, voice_ip, voice_port)
    finally:
        await cleanup_runner(ctx)

    return await export_and_summarize(ctx)


def build_arg_parser(user_config: dict | None = None) -> argparse.ArgumentParser:
    from blockchecks.cli.user_config import apply_parser_defaults

    p = argparse.ArgumentParser(
        prog="bs full",
        description="Mass strategy x coverage test + nfqws2 conf export",
    )
    add_store_args(p)
    if user_config:
        apply_parser_defaults(p, user_config)
    p.add_argument(
        "--db-batch",
        type=int,
        default=500,
        metavar="N",
        help="Buffer N DB writes before flush (0=immediate, default)",
    )
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
        "--zero-pass-warn",
        type=int,
        default=10,
        metavar="N",
        help="Warn if domain has 0%% PASS after N DB results (0=off, default 10)",
    )
    add_domain_filter_args(p)
    p.add_argument("--tcp-sources", default="standard,custom,configs,flowseal")
    p.add_argument("--udp-sources", default="custom,standard_udp")
    p.add_argument("--quic-sources", default="standard_quic")
    p.add_argument("--http-sources", default="custom,standard_http")
    p.add_argument("--no-http", action="store_true", help="Skip HTTP :80 strategy phase")
    p.add_argument("--scan-level", default="full", choices=["single", "fast", "full"])
    p.add_argument("--max", type=int, default=0, help="Cap strategies (0=uncapped)")
    p.add_argument("--parallel", type=int, default=effective_default_pool_size())
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--udp-timeout", type=float, default=3.0)
    p.add_argument("--protocol", default="tls12", choices=["tls12", "tls13"])
    p.add_argument(
        "--no-wssize",
        action="store_true",
        default=True,
        help="Skip wssize fallback on TLS 1.2 FAIL. Default ON for bs full (speed).",
    )
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
    p.add_argument("--isp-interface", default="eth3")
    p.add_argument("--prefix", default="/opt/etc/nfqws2")
    p.add_argument("--mode", default="auto", choices=["auto", "list", "all"])
    add_secure_dns_args(p, include_preflight=True)
    add_system_deps_args(p)
    add_curl_repeats_args(p, include_quic_timeout=True)
    add_family_gate_args(p)
    add_protocol_phase_args(p)
    add_curl_fanout_args(p)
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
    add_adaptive_args(p)
    add_lua_bridge_args(p)
    add_time_limit_args(p, include_export=True)
    return p


def main(argv: list[str] | None = None, user_config: dict | None = None) -> int:
    from blockchecks.cli.user_config import finalize_store_args, load_user_config
    from blockchecks.engine.paths import apply_pycache_prefix, ensure_dirs

    apply_pycache_prefix()
    ensure_dirs()
    cfg = user_config if user_config is not None else load_user_config()
    paths_cfg = cfg.get("paths") if isinstance(cfg.get("paths"), dict) else {}
    migrate_on = True if paths_cfg.get("migrate") is None else bool(paths_cfg.get("migrate"))
    from blockchecks.engine.paths import migrate_legacy_state_db

    migrate_legacy_state_db(enabled=migrate_on)
    p = build_arg_parser(cfg)
    args = p.parse_args(argv)
    finalize_store_args(args, cfg)
    validate_time_limit_args(p, args)
    deps_rc = ensure_system_deps_or_exit(args)
    if deps_rc:
        return deps_rc
    return asyncio.run(run_full(args))


if __name__ == "__main__":
    sys.exit(main())
