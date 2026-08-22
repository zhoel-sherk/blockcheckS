"""Export XDG data_block providers to a git checkout."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from blockchecks.data_block import export as data_block_export

log = logging.getLogger(__name__)


def cmd_data_block(args: argparse.Namespace) -> int:
    dest = getattr(args, "out", None)
    dest_path = Path(dest).expanduser() if dest else data_block_export.default_export_dest()
    if dest_path is None:
        log.error("%s", f"  ERROR: {data_block_export.CLONE_HINT}")
        return 1
    n = data_block_export.export_runtime_data_block(
        dest_path, provider=getattr(args, "provider", None) or None
    )
    if getattr(args, "git", False):
        if not (dest_path / ".git").exists():
            log.warning(
                "%s",
                f"  WARNING: {dest_path} has no .git; skipped commit/push. "
                f"{data_block_export.CLONE_HINT}",
            )
            return 1
        if not data_block_export.sync_exported(dest_path, push=True):
            return 1
    log.info("%s", f"  [data_block] export complete ({n} provider(s) → {dest_path})")
    return 0
