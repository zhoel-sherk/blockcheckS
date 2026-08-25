"""bs harvest-batch — export top PASS strategies for external validation."""

from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

from blockchecks.engine.paths import DEFAULT_DB_PATH, DEFAULT_OUT_DIR

log = logging.getLogger(__name__)


def cmd_harvest_batch(args: argparse.Namespace) -> int:
    from blockchecks.harvest_batch import (
        build_manifest,
        collect_harvest_candidates,
        render_batch_txt,
        write_confs,
    )

    db_path = getattr(args, "db", None) or DEFAULT_DB_PATH
    out_dir = Path(getattr(args, "out_dir", None) or (DEFAULT_OUT_DIR / "harvest")).expanduser()
    ts = time.strftime("%Y%m%d_%H%M%S")
    dest = out_dir / f"harvest_{ts}"
    dest.mkdir(parents=True, exist_ok=True)

    result = collect_harvest_candidates(
        db_path,
        proto=getattr(args, "proto", "tcp"),
        top=int(getattr(args, "top", 20)),
        min_domains=int(getattr(args, "min_domains", 2)),
    )
    if not result.candidates:
        log.error("%s", "  ERROR: no candidates matched filters (check --min-domains/--top)")
        return 1

    batch_path = dest / "batch.txt"
    batch_path.write_text(render_batch_txt(result), encoding="utf-8")
    manifest = build_manifest(
        result, db_path=db_path,
        proto=getattr(args, "proto", "tcp"),
        top=int(getattr(args, "top", 20)),
        min_domains=int(getattr(args, "min_domains", 2)),
    )
    import json

    manifest_path = dest / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    confs_info = ""
    if getattr(args, "write_confs", False):
        conf_dirs = write_confs(result, dest / "confs")
        confs_info = f", confs: {len(conf_dirs)}"

    sat = sum(1 for d in result.domains_meta if d.get("saturated"))
    log.info("%s", f"  harvest → {dest}")
    log.info("%s", f"  candidates: {len(result.candidates)}, "
                   f"batch.txt + manifest.json{confs_info}")
    log.info("%s", f"  domains: {len(result.domains_meta)} "
                   f"(saturated ≥85%: {sat}), "
                   f"quarantined excluded: {len(result.quarantined_excluded)}")
    return 0
