#!/usr/bin/env python3
"""Print McCabe histogram for src/ via ruff C90 (no radon).

Uses the live per-file C901 ignores from pyproject.toml. Exit 0 always.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_CC = re.compile(r"\((\d+) >")
_NAME = re.compile(r"`([^`]+)` is too complex")
BANDS = ((10, "8-10"), (15, "11-15"), (20, "16-20"), (25, "21-25"), (10**9, "26+"))


def _band(cc: int) -> str:
    return next(label for cap, label in BANDS if cc <= cap)


def main() -> int:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "src",
            "--select",
            "C90",
            "--config",
            "lint.mccabe.max-complexity=7",
            "--output-format",
            "json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        rows = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        print(proc.stderr or proc.stdout or "ruff produced no JSON", file=sys.stderr)
        return 1

    hits = [d for d in rows if d.get("code") == "C901"]
    ccs: list[int] = []
    hot: list[tuple[int, str, int, str]] = []
    by_file: Counter[str] = Counter()
    for d in hits:
        rel = d["filename"].split("/src/")[-1] if "/src/" in d["filename"] else d["filename"]
        msg = d.get("message", "")
        cc_m, name_m = _CC.search(msg), _NAME.search(msg)
        cc = int(cc_m.group(1)) if cc_m else 0
        name = name_m.group(1) if name_m else "?"
        row = int(d.get("location", {}).get("row") or 0)
        ccs.append(cc)
        by_file[rel] += 1
        hot.append((cc, rel, row, name))

    print(f"C901 at max-complexity=7: {len(ccs)} (pyproject per-file ignores applied)")
    if not ccs:
        print("  (none)")
        return 0
    bands = Counter(_band(c) for c in ccs if c >= 8)
    print("bands:", dict(sorted(bands.items(), key=lambda kv: kv[0])))
    print("max cc:", max(ccs))
    print("leftover if max=10/12/15/18/20/25:",
          *[sum(c > cap for c in ccs) for cap in (10, 12, 15, 18, 20, 25)])
    print("cc>=18:")
    for cc, rel, row, name in sorted(hot, reverse=True):
        if cc >= 18:
            print(f"  {cc:2d}  {rel}:{row}  {name}")
    print("top files:")
    for rel, n in by_file.most_common(15):
        print(f"  {n:3d} {rel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
