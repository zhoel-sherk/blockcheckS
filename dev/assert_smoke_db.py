#!/usr/bin/env python3
"""Post-run checks for live smokes: harvest APPLIED + lua_bridge log.

Usage:
  python3 dev/assert_smoke_db.py --db PATH [--log PATH]
Exit 0 if OK, 1 if a contract is broken.
"""

from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from pathlib import Path


def _false_pass_count(db: Path) -> int:
    con = sqlite3.connect(db)
    try:
        n = con.execute(
            """
            SELECT COUNT(*) FROM tcp_results
            WHERE status = 'PASS' AND coalesce(bridge_applied, 0) != 1
            """
        ).fetchone()[0]
    except sqlite3.OperationalError:
        return 0
    finally:
        con.close()
    return int(n)


def _check_log(text: str) -> list[str]:
    fails: list[str] = []
    if "backend=" in text and "backend=lua_bridge" not in text:
        fails.append("log has backend= but not lua_bridge")
    drift = len(re.findall(r"PASS without APPLIED", text))
    if drift > 2:
        fails.append(f"PASS without APPLIED storm ({drift} hits)")
    if re.search(r"heartbeat age is None.*not stale", text, re.I):
        fails.append("missing heartbeat treated as live")
    return fails


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--db", type=Path, default=None)
    p.add_argument("--log", type=Path, default=None)
    p.add_argument("--require-backend", action="store_true")
    args = p.parse_args()
    errors: list[str] = []
    if args.db is not None:
        if not args.db.is_file():
            errors.append(f"missing db {args.db}")
        elif (n := _false_pass_count(args.db)):
            errors.append(f"{n} PASS rows without bridge_applied=1 in {args.db}")
    if args.log is not None:
        if not args.log.is_file():
            errors.append(f"missing log {args.log}")
        else:
            text = args.log.read_text(encoding="utf-8", errors="replace")
            errors.extend(_check_log(text))
            if args.require_backend and "backend=lua_bridge" not in text:
                errors.append("log missing backend=lua_bridge")
    if errors:
        print("assert_smoke_db FAIL:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    print("assert_smoke_db OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
