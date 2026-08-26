"""bs gc — dry-run (default) prune of debug logs / summaries / harvest / caches / DB rows."""

from __future__ import annotations

import argparse
import logging

from blockchecks.engine.gc import (
    DEFAULT_MAX_AGE_DAYS,
    NFQWS2_LOG_KEEP,
    apply_gc,
    collect_gc,
    prune_db_results,
)
from blockchecks.engine.paths import DEFAULT_DB_PATH

log = logging.getLogger(__name__)


def cmd_gc(args: argparse.Namespace) -> int:
    dry = not bool(getattr(args, "apply", False))
    plan = collect_gc(
        max_age_days=float(getattr(args, "max_age_days", DEFAULT_MAX_AGE_DAYS)),
        nfqws2_keep=int(getattr(args, "nfqws2_keep", NFQWS2_LOG_KEEP)),
    )
    for item in plan.deletes:
        log.info("%s", f"  {'DRY' if dry else 'DEL'} {item.reason} {item.bytes}B {item.path}")
    for item in plan.skipped:
        log.info("%s", f"  SKIP {item.reason} {item.path}")
    apply_gc(plan, dry_run=dry)
    db_days = getattr(args, "db_days", None)
    if db_days is not None:
        db_path = getattr(args, "db", None)
        stats = prune_db_results(
            db_path if db_path is not None else DEFAULT_DB_PATH,
            max_age_days=float(db_days),
            dry_run=dry,
            orphan_strategies=bool(getattr(args, "orphan_strategies", False)),
        )
        if stats.skipped_lock:
            log.warning("gc db skipped DELETE (run.lock present) path=%s", stats.db_path)
    if dry and (plan.deletes or db_days is not None):
        log.info("%s", "  re-run with --apply to delete")
    return 0
