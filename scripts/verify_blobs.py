#!/usr/bin/env python3
"""Verify blob alias resolution and file integrity (BLOB-2)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Allow running from scripts/ without install
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from blockchecks.engine.blob_aliases import BLOB_ALIAS_MAP, resolve_blob_path  # noqa: E402
from blockchecks.engine.config import BLOB_DIR  # noqa: E402

_MIN_SIZE = 20
_OPTIONAL = frozenset()  # core aliases are baked in-repo blobs/


def main() -> int:
    blobs_dir = os.environ.get("BLOCKCHECKS_BLOBS", BLOB_DIR)
    ok = fail = skip = 0
    print(f"verify_blobs: {blobs_dir} ({len(BLOB_ALIAS_MAP)} aliases)")
    for alias, _fname in sorted(BLOB_ALIAS_MAP.items()):
        path = resolve_blob_path(alias, blobs_dir)
        if not path or not os.path.isfile(path):
            if alias in _OPTIONAL:
                print(f"  WARN  {alias:20} missing (optional)")
                skip += 1
            else:
                print(f"  FAIL  {alias:20} not resolved")
                fail += 1
            continue
        size = os.path.getsize(path)
        if size < _MIN_SIZE:
            print(f"  FAIL  {alias:20} too small ({size}B) {path}")
            fail += 1
            continue
        print(f"  OK    {alias:20} {size:5}B  {os.path.basename(path)}")
        ok += 1
    print(f"summary: ok={ok} fail={fail} optional_missing={skip}")
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
