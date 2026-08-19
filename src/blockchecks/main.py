"""bs full — mass strategy×coverage orchestrator + conf export."""

from __future__ import annotations

import argparse
import asyncio
import sys

from blockchecks.cli.parser import (
    add_campaign_args,
    ensure_system_deps_or_exit,
)
from blockchecks.cli.profiles import apply_profile
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
from blockchecks.terminal import init_terminal

init_terminal()


async def run_full(args) -> int:
    from blockchecks.service.run_control import run_session

    async with run_session("full", db_path=getattr(args, "db", None)):
        return await _run_full_campaign(args)


async def _run_full_campaign(args) -> int:
    apply_profile(args)
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
    add_campaign_args(p, mode="full")
    if user_config:
        apply_parser_defaults(p, user_config)
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
