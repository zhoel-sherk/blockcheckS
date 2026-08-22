#!/usr/bin/env python3
"""AQ8: benchmark PASS discovery rate vs job order in state.db."""

from __future__ import annotations

import argparse
import asyncio
import sys

# Allow running from repo without install
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src"))

import aiosqlite

from blockchecks.engine.paths import DEFAULT_DB_PATH


async def analyze(db_path: str, domain: str | None) -> dict:
    async with aiosqlite.connect(db_path) as db:
        domain_clause = ""
        params: list = []
        if domain:
            domain_clause = "AND t.domain = ?"
            params.append(domain)

        rows = await (
            await db.execute(
                f"""
                SELECT s.name, t.domain, t.status, t.timestamp, t.id
                FROM tcp_results t
                JOIN strategies s ON t.strategy_id = s.id
                WHERE s.proto = 'tcp' {domain_clause}
                ORDER BY t.id ASC
                """,
                params,
            )
        ).fetchall()

    # First PASS index per (strategy, domain)
    first_pass_idx: dict[tuple[str, str], int] = {}
    total_jobs = len(rows)
    for i, (strat, dom, status, _ts, _id) in enumerate(rows):
        key = (strat, dom)
        if status == "PASS" and key not in first_pass_idx:
            first_pass_idx[key] = i

    if not first_pass_idx:
        return {
            "total_jobs": total_jobs,
            "unique_passes": 0,
            "before_half": 0,
            "pct_before_half": 0.0,
        }

    half = max(1, total_jobs // 2)
    before_half = sum(1 for idx in first_pass_idx.values() if idx < half)
    return {
        "total_jobs": total_jobs,
        "unique_passes": len(first_pass_idx),
        "before_half": before_half,
        "pct_before_half": 100.0 * before_half / len(first_pass_idx),
        "half_mark": half,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="AQ8: PASS discovery before 50% jobs benchmark")
    p.add_argument("--db", default=str(DEFAULT_DB_PATH))
    p.add_argument("-d", "--domain", default=None, help="Filter to one domain")
    p.add_argument(
        "--target",
        type=float,
        default=90.0,
        help="Target %% of passes found before half (default 90)",
    )
    args = p.parse_args(argv)

    stats = asyncio.run(analyze(args.db, args.domain))
    print(f"DB: {args.db}")
    if args.domain:
        print(f"Domain: {args.domain}")
    print(f"Total jobs (tcp_results rows): {stats['total_jobs']}")
    print(f"Unique PASS (strategy×domain): {stats['unique_passes']}")
    if stats["unique_passes"]:
        print(f"First PASS before job #{stats['half_mark']}: {stats['before_half']}")
        print(f"Rate: {stats['pct_before_half']:.1f}% (target {args.target:.0f}%)")
        if stats["pct_before_half"] >= args.target:
            print("RESULT: PASS hypothesis met")
            return 0
        print("RESULT: below target (shuffle/AQ may help)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
