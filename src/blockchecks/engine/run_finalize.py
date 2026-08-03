"""Graceful run finalization: export, summary JSON, AQ weights."""

from __future__ import annotations

import json
import os
import time
from typing import Any

from blockchecks.engine.adaptive_runner import persist_adaptive_weights
from blockchecks.engine.paths import RUNTIME_LOGS_DIR
from blockchecks.engine.run_deadline import RunDeadline
from blockchecks.engine.store import RunStateStore
from blockchecks.nfconf import export_configs


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
