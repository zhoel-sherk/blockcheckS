"""bs gc — dry-run (default) prune of debug logs / summaries / harvest / caches."""

from __future__ import annotations

import argparse
import logging

from blockchecks.engine.gc import DEFAULT_MAX_AGE_DAYS, NFQWS2_LOG_KEEP, apply_gc, collect_gc

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
    if dry and plan.deletes:
        log.info("%s", "  re-run with --apply to delete")
    return 0
