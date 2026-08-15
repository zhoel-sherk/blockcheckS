#!/usr/bin/env python3
"""Preset manifest helper — check completeness / regenerate counts.

Usage:
  python scripts/gen_presets_manifest.py check    # verify manifest matches disk
  python scripts/gen_presets_manifest.py counts   # print current file → count map
"""

from __future__ import annotations

import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
STRATEGIES_DIR = ROOT / "presets" / "strategies"
DOMAINS_DIR = ROOT / "presets" / "domains"
MANIFEST = ROOT / "presets" / "manifest.toml"

_EXTS = ("*.tls", "*.txt", "*.http", "*.quic", "*.udp")


def _nonempty_lines(path: Path) -> list[str]:
    return [
        ln.strip()
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]


def strategy_files() -> set[str]:
    out: set[str] = set()
    for pat in _EXTS:
        out |= {p.name for p in STRATEGIES_DIR.glob(pat)}
    return out


def domain_files() -> set[str]:
    return {p.name for p in DOMAINS_DIR.glob("*.txt")}


def check() -> int:
    with MANIFEST.open("rb") as f:
        data = tomllib.load(f)
    s_manifest = {v["file"] for v in data["strategies"].values()}
    d_manifest = {v["file"] for v in data["domains"].values()}
    s_disk = strategy_files()
    d_disk = domain_files()
    rc = 0
    if s_manifest != s_disk:
        print(
            f"STRATEGIES mismatch: manifest-only={s_manifest - s_disk}, "
            f"disk-only={s_disk - s_manifest}"
        )
        rc = 1
    if d_manifest != d_disk:
        print(
            f"DOMAINS mismatch: manifest-only={d_manifest - d_disk}, "
            f"disk-only={d_disk - d_manifest}"
        )
        rc = 1
    # Domain counts.
    for entry in data["domains"].values():
        n = len(_nonempty_lines(DOMAINS_DIR / entry["file"]))
        if n != entry["count"]:
            print(f"  count {entry['file']}: manifest={entry['count']} actual={n}")
            rc = 1
    if rc:
        print("manifest is OUT OF DATE")
    else:
        print("manifest OK")
    return rc


def counts() -> int:
    for path in sorted(DOMAINS_DIR.glob("*.txt")):
        print(f"{path.name}: {len(_nonempty_lines(path))}")
    return 0


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "check":
        return check()
    if cmd == "counts":
        return counts()
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
