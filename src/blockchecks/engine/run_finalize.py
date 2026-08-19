"""Graceful run finalization: export, summary JSON, AQ weights."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from blockchecks.engine.adaptive_runner import persist_adaptive_weights
from blockchecks.engine.paths import RUNTIME_LOGS_DIR
from blockchecks.engine.run_deadline import RunDeadline
from blockchecks.engine.store import RunStateStore
from blockchecks.nfconf import export_configs


def rank_pass_strategies_for_export(
    rows: list[dict[str, Any]], *, tcp_n: int = 5, udp_n: int = 5
) -> tuple[list[str], list[str]]:
    """Pick TCP/UDP cores for best_config: lowest latency, UDP prefers discord_udp."""

    def _latency(row: dict[str, Any]) -> float:
        try:
            return float(row.get("latency_ms") or 1e9)
        except (TypeError, ValueError):
            return 1e9

    def _unique(ordered: list[dict[str, Any]]) -> list[str]:
        return list(dict.fromkeys(r["strategy"] for r in ordered if r.get("strategy")))

    tcp_rows = sorted(
        (r for r in rows if r.get("protocol") == "tcp"),
        key=_latency,
    )
    udp_rows = sorted(
        (r for r in rows if r.get("protocol") == "udp"),
        key=lambda r: (0 if "discord_udp" in str(r.get("strategy") or "") else 1, _latency(r)),
    )
    return _unique(tcp_rows)[:tcp_n], _unique(udp_rows)[:udp_n]


async def maybe_write_best_config_data_block() -> None:
    """Write the best nfqws2 config to data_block/providers/<p>/best_config.conf.

    Best-effort: silently skipped when the submodule / provider is unavailable
    or strategies.db has no recorded passes.  Uses approved pass strategies
    (falling back to any pass) to keep the config stable.
    """
    try:
        from blockchecks.data_block.provider import get_provider_dir
        from blockchecks.data_block.store import ProviderStore
        from blockchecks.engine.conf_builder import build_keenetic_conf

        store = ProviderStore(get_provider_dir())
        if not store.strategies_db.is_file():
            return
        rows = await store.pass_strategies(approved_only=True)
        if not rows:
            rows = await store.pass_strategies()
        if not rows:
            return
        tcp, udp = rank_pass_strategies_for_export(rows)
        if not tcp and not udp:
            return
        comment = f"blockcheckS best_config ({_now()}) domains={len(rows)}"
        content = build_keenetic_conf(
            tcp_strategies=tcp,
            udp_strategies=udp,
            comment=comment,
        )
        store.write_best_config(content)
    except Exception:
        pass


async def maybe_sync_data_block(args=None) -> None:
    """Commit+push data_block/ when the ``--data-block-sync`` flag is set.

    No-op otherwise (keeps the submodule clean after routine scans).
    """
    enabled = False
    if args is not None:
        enabled = bool(getattr(args, "data_block_sync", False))
    if not enabled:
        import sys

        enabled = "--data-block-sync" in sys.argv[1:]
    if not enabled:
        return
    try:
        from blockchecks.data_block.provider import get_provider_dir
        from blockchecks.data_block.store import ProviderStore

        store = ProviderStore(get_provider_dir())
        store.sync_commit(push=True)
    except Exception:
        pass


def _now() -> str:
    import time

    return time.strftime("%Y-%m-%dT%H:%M:%S")


def should_export(
    args,
    *,
    stop_set: bool,
    _deadline: RunDeadline | None,
    pass_count: int,
) -> bool:
    if getattr(args, "no_export_on_stop", False) and stop_set:
        return False
    if not getattr(args, "out_dir", None):
        return False
    return not (stop_set and pass_count <= 0)


async def maybe_export_configs(
    store: RunStateStore,
    args,
    *,
    primary: str,
    domains_file: str | None,
    stop_set: bool,
    deadline: RunDeadline | None,
) -> dict[str, Any] | None:
    await store.flush()
    passes = await store.count_tcp_passes()
    if not should_export(args, stop_set=stop_set, _deadline=deadline, pass_count=passes):
        return None
    return await export_configs(
        store=store,
        domain=primary,
        limit=getattr(args, "export_limit", 3),
        out_dir=args.out_dir,
        isp_interface=getattr(args, "isp_interface", "eth3"),
        prefix=getattr(args, "prefix", "/opt/etc/nfqws2"),
        mode=getattr(args, "mode", "auto"),
        domains_file=domains_file,
        common_only=not getattr(args, "no_common_only", False),
    )


def write_run_summary(
    out_dir: str,
    payload: dict[str, Any],
) -> str:
    base = out_dir or str(RUNTIME_LOGS_DIR)
    os.makedirs(base, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(base, f"run_summary_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")
    from blockchecks.engine.paths import reclaim_sudo_ownership

    reclaim_sudo_ownership(Path(path))
    return path


async def finalize_db_and_weights(
    store: RunStateStore,
    *,
    aq_weights=None,
    save_weights: bool = True,
) -> None:
    await store.flush()
    if save_weights and aq_weights is not None:
        await persist_adaptive_weights(store, aq_weights)


def run_exit_code(_stop_set: bool, deadline: RunDeadline | None, signal_hit: bool) -> int:
    if signal_hit and not (deadline and deadline.triggered):
        return 130
    return 0
