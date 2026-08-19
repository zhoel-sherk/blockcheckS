"""Phase 11 A9 — nfqws2 settle × curl timeout benchmark."""

from __future__ import annotations

import asyncio
import time

from blockchecks.checkers.dns_secure import prepare_dns_for_run
from blockchecks.engine.async_runner import AsyncTestRunner, _run_tcp_check
from blockchecks.engine.config import SECURE_DNS_DEFAULT
from blockchecks.engine.matrix_generator import StrategyItem
from blockchecks.engine.settle_profile import (
    DEFAULT_PROFILE_PATH,
    build_profile_from_rows,
    save_profile,
)
from blockchecks.engine.strategy_loader import StrategyLoader
from blockchecks.terminal import CYAN, GREEN, RED, RESET, YELLOW

DEFAULT_SETTLE = (0.1, 0.2, 0.5, 1.0, 2.0)
DEFAULT_CURL = (0.5, 1.0, 1.5, 2.0)


def _parse_floats(raw: str, default: tuple[float, ...]) -> tuple[float, ...]:
    if not raw:
        return default
    return tuple(float(x.strip()) for x in raw.split(",") if x.strip())


def _load_strategies(args) -> list[StrategyItem]:
    from blockchecks.cli.presets import PresetPathError, resolve_strategy_preset

    preset = getattr(args, "strategy_preset", None) or "timeout-benchmark"
    raw: list[str] = []
    try:
        path = resolve_strategy_preset(preset)
        raw = StrategyLoader.from_file(str(path))
    except PresetPathError as e:
        print(f"{RED}ERROR: {e}{RESET}")
        return []
    except FileNotFoundError:
        if getattr(args, "strategy", None):
            raw = StrategyLoader.from_string(args.strategy)
        else:
            print(f"{RED}ERROR: strategy preset '{preset}' not found{RESET}")
            return []
    return [StrategyItem(f"bench_{i}", s) for i, s in enumerate(raw)]


async def cmd_bench_settle(args) -> int:
    """Grid benchmark: settle_max × curl timeout per strategy (A9)."""
    domain = args.domain
    settle_times = _parse_floats(getattr(args, "settle_times", ""), DEFAULT_SETTLE)
    curl_timeouts = _parse_floats(getattr(args, "curl_timeouts", ""), DEFAULT_CURL)
    items = _load_strategies(args)
    if not items:
        return 1
    if len(items) > getattr(args, "max_strategies", 3):
        items = items[: getattr(args, "max_strategies", 3)]

    from blockchecks.data_block.provider import provider_name

    provider_name(allow_detect=True)
    secure_dns = SECURE_DNS_DEFAULT and not getattr(args, "no_secure_dns", False)
    dns_cache, _, dns_rc = prepare_dns_for_run(
        [domain],
        secure_dns=secure_dns,
        skip_audit=True,
        allow_hijack=True,
    )
    if dns_rc:
        return dns_rc

    print(f"\n  {CYAN}bench-settle — {domain}{RESET}")
    print(f"  Strategies: {len(items)}  settle={settle_times}  curl={curl_timeouts}")

    runner = AsyncTestRunner(pool_size=1, secure_dns=secure_dns, dns_cache=dns_cache)
    await runner.start()
    ns_name = await runner.pool.acquire()
    resolved = dns_cache.primary_ip(domain) if dns_cache else None

    rows: list[dict] = []
    try:
        for item in items:
            for settle_max in settle_times:
                for curl_t in curl_timeouts:
                    t0 = time.perf_counter()
                    data = await asyncio.to_thread(
                        _run_tcp_check,
                        ns_name,
                        item.strategy,
                        domain,
                        curl_t,
                        item.is_config,
                        runner.python,
                        False,
                        resolved,
                        1,
                        False,
                        "",
                        "tls12",
                        settle_max,
                        None,
                    )
                    total_ms = (time.perf_counter() - t0) * 1000
                    ok = data.get("success")
                    rows.append(
                        {
                            "strategy": item.label[:28],
                            "strategy_full": item.strategy,
                            "settle_max": settle_max,
                            "curl_t": curl_t,
                            "settle_ms": data.get("settle_ms", 0),
                            "total_ms": round(total_ms, 0),
                            "latency_ms": round(data.get("latency_ms", 0), 0),
                            "http": data.get("http_code", 0),
                            "ok": ok,
                        }
                    )
                    mark = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
                    print(
                        f"  {item.label[:24]:24s} settle={settle_max:.1f}s "
                        f"curl={curl_t:.1f}s → {mark} "
                        f"settle={data.get('settle_ms', 0):.0f}ms "
                        f"lat={data.get('latency_ms', 0):.0f}ms "
                        f"tot={total_ms:.0f}ms"
                    )
    finally:
        await runner.pool.release(ns_name)
        await runner.stop()

    # Recommend minimum settle where PASS rate holds
    pass_settles = sorted({r["settle_max"] for r in rows if r["ok"]})
    out_path = None
    if not getattr(args, "no_write_profile", False):
        out_path = getattr(args, "write_profile", None) or DEFAULT_PROFILE_PATH
    if out_path and rows:
        profile = build_profile_from_rows(rows, domain=domain)
        saved = save_profile(profile, out_path)
        print(f"\n  {GREEN}Profile written: {saved}{RESET}")
        if profile.defaults:
            print(
                f"  defaults: settle_max={profile.defaults.settle_max}s "
                f"curl={profile.defaults.curl_timeout}s "
                f"({len(profile.strategies)} strategies)"
            )
    elif pass_settles:
        print(
            f"\n  {GREEN}Min settle with PASS: {pass_settles[0]:.1f}s "
            f"(use BLOCKCHECKS_NFQWS2_SETTLE_MAX={pass_settles[0]}){RESET}"
        )
    else:
        print(f"\n  {YELLOW}No PASS in grid — check domain/strategy/preflight{RESET}")
    return 0
