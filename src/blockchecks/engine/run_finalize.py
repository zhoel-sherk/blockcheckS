"""Graceful run finalization: export, summary JSON, AQ weights."""

from __future__ import annotations

import json
import os
import time
from typing import Any

from blockchecks.engine.adaptive_runner import persist_adaptive_weights
from blockchecks.engine.db_logger import StateDB
from blockchecks.engine.run_deadline import RunDeadline
from blockchecks.nfconf import export_configs


async def count_tcp_passes(db: StateDB, domain: str | None = None) -> int:
    if domain:
        stats = await db.domain_pass_stats(domain, protos=("tcp",))
        return int(stats.get("passed", 0))
    async with __import__("aiosqlite").connect(db.db_path) as conn:
        row = await (
            await conn.execute(
                """SELECT COUNT(*) FROM tcp_results t
                   JOIN strategies s ON t.strategy_id=s.id
                   WHERE t.status='PASS' AND s.proto='tcp'"""
            )
        ).fetchone()
    return int(row[0] or 0)


def should_export(
    args,
    *,
    stop_set: bool,
    deadline: RunDeadline | None,
    pass_count: int,
) -> bool:
    if getattr(args, "no_export_on_stop", False) and stop_set:
        return False
    if not getattr(args, "out_dir", None):
        return False
    if stop_set and pass_count <= 0:
        return False
    return True


async def maybe_export_configs(
    db: StateDB,
    args,
    *,
    primary: str,
    domains_file: str | None,
    stop_set: bool,
    deadline: RunDeadline | None,
) -> dict[str, Any] | None:
    passes = await count_tcp_passes(db)
    if not should_export(args, stop_set=stop_set, deadline=deadline, pass_count=passes):
        return None
    return await export_configs(
        db_path=db.db_path,
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
    os.makedirs(out_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out_dir, f"run_summary_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return path


async def finalize_db_and_weights(
    db: StateDB,
    *,
    aq_weights=None,
    save_weights: bool = True,
) -> None:
    await db.flush()
    if save_weights and aq_weights is not None:
        await persist_adaptive_weights(db, aq_weights)


def run_exit_code(stop_set: bool, deadline: RunDeadline | None, signal_hit: bool) -> int:
    if signal_hit and not (deadline and deadline.triggered):
        return 130
    return 0
