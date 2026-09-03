"""Async TCP x UDP pair matrix command."""

import asyncio
import logging
import time

from blockchecks.cli.commands.pair_phases import (
    STANDARD_TCP_SOURCES,
    StopHandlerState,
    build_pair_runner,
    discover_voice_endpoints,
    finalize_pair_run,
    load_strategy_items,
    prepare_dns_and_preflight,
    print_pair_banner,
    register_stop_handlers,
    resolve_preset_domains,
    resolve_resume_checkpoint,
    run_adaptive_pair_phase,
    run_standard_pair_phase,
    validate_pair_domain,
)
from blockchecks.cli.presets import list_presets
from blockchecks.cli.profiles import apply_profile
from blockchecks.engine.config import (
    DEFAULT_CURL_PARALLEL,
    MAX_CURL_PARALLEL,
    effective_default_pool_size,
)
from blockchecks.engine.run_deadline import RunDeadline
from blockchecks.engine.run_finalize import finalize_db_and_weights, run_exit_code
from blockchecks.engine.store import (
    DEFAULT_DB_BATCH,
    campaign_args_hash,
    matrix_fingerprint,
    open_run_store,
)
from blockchecks.terminal import CYAN, RESET, YELLOW

log = logging.getLogger(__name__)


async def cmd_pair(args):
    """TCP×UDP pair matrix with generator + async runner."""
    if getattr(args, "list_presets", False):
        list_presets()
        return 0

    from blockchecks.service.run_control import run_session

    cmd = "scan" if getattr(args, "tcp_only", False) else "pair"
    async with run_session(cmd, db_path=getattr(args, "db", None)):
        return await _cmd_pair_run(args)


async def _cmd_pair_run(args):
    apply_profile(args)
    db = open_run_store(
        args.db,
        batch_size=int(getattr(args, "db_batch", DEFAULT_DB_BATCH)),
        resume=bool(getattr(args, "resume", False)),
    )
    await db.init()
    try:

        preset_domains, preset_rc = resolve_preset_domains(args)
        if preset_rc is not None:
            return preset_rc

        domain_rc = validate_pair_domain(args, preset_domains)
        if domain_rc is not None:
            return domain_rc

        raw_domain = getattr(args, "domain", None)
        if isinstance(raw_domain, str):
            explicit_domains = [raw_domain] if raw_domain else []
        else:
            explicit_domains = list(raw_domain or [])
        if explicit_domains:
            preset_domains = list(dict.fromkeys((preset_domains or []) + explicit_domains))
            args.domain = preset_domains[0]

        pool_size = args.parallel or effective_default_pool_size()
        dns_result = await prepare_dns_and_preflight(args, preset_domains, store=db)
        if dns_result.exit_code is not None:
            return dns_result.exit_code

        runner = build_pair_runner(args, db, dns_result.dns_cache, dns_result.dns_audits, pool_size)
        stop_event = asyncio.Event()
        deadline = RunDeadline.from_args(stop_event, args)
        stop_state = StopHandlerState()
        aq_result = None
        tcp_passed = 0
        pairs = []

        loop = asyncio.get_running_loop()
        restore_signals = register_stop_handlers(loop, stop_state, deadline, stop_event)

        if deadline:
            deadline.arm()
            await deadline.start_background()
            log.info("%s", f"  Time limit: {deadline.budget_label()}")

        try:
            await runner.start()

            voice_ctx, voice_rc = await discover_voice_endpoints(args)
            if voice_rc is not None:
                return voice_rc

            strategies = await load_strategy_items(args, db)
            if strategies.error_code is not None:
                return strategies.error_code

            banner_rc = print_pair_banner(
                args,
                preset_domains,
                strategies.tcp_items,
                strategies.udp_items,
                voice_ctx.voice_ip,
                voice_ctx.voice_port,
                voice_ctx.full_voice,
                pool_size,
            )
            if banner_rc is not None:
                return banner_rc

            domains_to_test = preset_domains if preset_domains else [args.domain]
            fp = matrix_fingerprint(
                [i.strategy for i in strategies.tcp_items],
                [i.strategy for i in strategies.udp_items],
                getattr(args, "scan_level", "fast"),
                getattr(args, "max", 100),
            )
            runner.matrix_fingerprint = fp
            await db.begin_run(
                fingerprint=fp,
                args_hash=campaign_args_hash(args),
            )

            resume_from, resume_rc = await resolve_resume_checkpoint(args, db, fp)
            if resume_rc is not None:
                return resume_rc

            if stop_event.is_set():
                return run_exit_code(True, deadline, stop_state.signal_interrupted)

            t0 = time.perf_counter()
            scan_level = getattr(args, "scan_level", "fast")
            use_adaptive = not bool(getattr(args, "no_adaptive", False))
            protocol = getattr(args, "protocol", "tls12") or "tls12"
            curl_parallel = max(
                1, min(getattr(args, "curl_parallel", DEFAULT_CURL_PARALLEL), MAX_CURL_PARALLEL)
            )
            if (getattr(args, "fan_out", False) or use_adaptive) and curl_parallel <= 1:
                curl_parallel = min(max(4, DEFAULT_CURL_PARALLEL), MAX_CURL_PARALLEL)
            use_family_gates = (
                scan_level != "full"
                and not getattr(args, "no_family_gates", False)
                and not use_adaptive
                and any(s in STANDARD_TCP_SOURCES for s in strategies.tcp_sources_list)
            )

            if use_adaptive:
                phase = await run_adaptive_pair_phase(
                    args,
                    runner,
                    db,
                    strategies.tcp_items,
                    strategies.udp_items,
                    domains_to_test,
                    voice_ctx.voice_ip,
                    voice_ctx.voice_port,
                    voice_ctx.full_voice,
                    resume_from,
                    fp,
                    stop_event,
                    curl_parallel,
                    protocol,
                    multi_eps=voice_ctx.multi_eps,
                )
            else:
                phase = await run_standard_pair_phase(
                    args,
                    runner,
                    strategies.tcp_items,
                    strategies.udp_items,
                    domains_to_test,
                    voice_ctx.voice_ip,
                    voice_ctx.voice_port,
                    voice_ctx.full_voice,
                    resume_from,
                    fp,
                    stop_event,
                    scan_level,
                    use_family_gates,
                    strategies.run_set,
                    multi_eps=voice_ctx.multi_eps,
                )

            tcp_passed = phase.tcp_passed
            pairs = phase.pairs
            aq_result = phase.aq_result

            if stop_event.is_set() and deadline and deadline.triggered:
                log.info(
                    "%s",
                    f"\n  {YELLOW}TIME LIMIT reached ({deadline.budget_label()})"
                    f" — skipping optional phases{RESET}",
                )

            elapsed = time.perf_counter() - t0
            log.info("%s", f"\n  {CYAN}Done in {elapsed:.0f}s{RESET}")

        finally:
            restore_signals()
            if deadline:
                await deadline.cancel()
            await finalize_db_and_weights(db, save_weights=False)
            await runner.stop()

        return await finalize_pair_run(
            args,
            db,
            deadline,
            stop_event,
            stop_state,
            tcp_passed,
            pairs,
            aq_result,
            preset_domains,
        )
    finally:
        # ST-2: long-lived writer держит поток aiosqlite — без close()
        # процесс висит после завершения работы (найдено смоком).
        log.debug("SqliteRunStore.close begin")
        await db.close()
        log.debug("SqliteRunStore.close done")
