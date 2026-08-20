"""Write blockchecks.shortlist/v1 JSON."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

from blockchecks.engine.domain_loader import DEFAULT_DOMAINS_FILE, read_domain_lines
from blockchecks.engine.paths import DEFAULT_DB_PATH, DEFAULT_SHORTLIST_DIR, expand_path
from blockchecks.engine.store import RunStateStore, open_run_store
from blockchecks.nfconf import collect_export_strategies

SCHEMA = "blockchecks.shortlist/v1"


async def build_shortlist_entries(
    db: RunStateStore,
    *,
    domains: list[str],
    limit: int = 10,
    include_common: bool = False,
) -> dict[str, Any]:
    """Build shortlist payload from StateDB."""
    primary = domains[0] if domains else "discord.com"

    common_tcp: list[dict[str, Any]] = []
    if include_common and len(domains) > 1:
        for row in await db.get_common_tcp(domains, limit=limit):
            cfg = await db.get_strategy_config(row["strategy"], "tcp")
            common_tcp.append(
                {
                    "label": row["strategy"],
                    "strategy": cfg or row["strategy"],
                    "domains_pass": domains,
                    "avg_latency_ms": row.get("avg_latency_ms", 0.0),
                }
            )

    tcp_rows: list[dict[str, Any]] = []
    for row in await db.get_best_tcp(primary, limit=limit):
        cfg = await db.get_strategy_config(row["strategy"], "tcp")
        tcp_rows.append(
            {
                "label": row["strategy"],
                "strategy": cfg or row["strategy"],
                "domains_pass": [primary],
                "avg_latency_ms": row.get("latency_ms", 0.0),
            }
        )

    if not tcp_rows:
        for row in await db.get_best_by_coverage(limit=limit):
            cfg = await db.get_strategy_config(row["strategy"], "tcp")
            tcp_rows.append(
                {
                    "label": row["strategy"],
                    "strategy": cfg or row["strategy"],
                    "domains_pass_count": row.get("domains_passed", 0),
                    "avg_latency_ms": row.get("avg_latency_ms", 0.0),
                }
            )

    udp_rows: list[dict[str, Any]] = []
    for row in await db.get_best_udp(limit=limit):
        cfg = await db.get_strategy_config(row["strategy"], "udp")
        udp_rows.append(
            {
                "label": row["strategy"],
                "strategy": cfg or row["strategy"],
                "target": row.get("target", ""),
                "latency_ms": row.get("latency_ms", 0.0),
            }
        )

    quic_rows: list[dict[str, Any]] = []
    for row in await db.get_best_quic(primary, limit=limit):
        cfg = await db.get_strategy_config(row["strategy"], "quic")
        quic_rows.append(
            {
                "label": row["strategy"],
                "strategy": cfg or row["strategy"],
                "domains_pass": [primary],
                "latency_ms": row.get("latency_ms", 0.0),
            }
        )

    # Fallback export strings (same as nfconf) when DB has no winners yet
    if not tcp_rows and not udp_rows and not quic_rows:
        tcp_s, udp_s, quic_s = await collect_export_strategies(
            db, domain=primary, limit=limit, domains=domains, common_only=len(domains) > 1
        )
        tcp_rows = [
            {"label": f"export_{i}", "strategy": s, "domains_pass": []} for i, s in enumerate(tcp_s)
        ]
        udp_rows = [{"label": f"export_{i}", "strategy": s} for i, s in enumerate(udp_s)]
        quic_rows = [
            {"label": f"export_{i}", "strategy": s, "domains_pass": []}
            for i, s in enumerate(quic_s)
        ]

    return {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_db": db.path.name,
        "domains": domains,
        "tcp": tcp_rows,
        "udp": udp_rows,
        "quic": quic_rows,
        "common_tcp": common_tcp,
    }


async def export_shortlist_json(
    *,
    db_path: str | None = None,
    domains_file: str | None = None,
    domain: str = "discord.com",
    limit: int = 10,
    output: str | None = None,
    include_common: bool = False,
) -> dict[str, Any]:
    db = open_run_store(db_path)
    await db.init()
    out_path = expand_path(
        output,
        default=DEFAULT_SHORTLIST_DIR / "shortlist.json",
    )

    if domains_file and os.path.exists(domains_file):
        domains = read_domain_lines(domains_file)
    elif os.path.exists(DEFAULT_DOMAINS_FILE):
        domains = read_domain_lines(DEFAULT_DOMAINS_FILE)
    else:
        domains = [domain]

    payload = await build_shortlist_entries(
        db, domains=domains, limit=limit, include_common=include_common
    )
    os.makedirs(out_path.parent, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return payload


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Export blockchecks.shortlist/v1 JSON")
    p.add_argument("--db", default=None, help=f"State DB (default: {DEFAULT_DB_PATH})")
    p.add_argument("--domains-file", default=None)
    p.add_argument("-d", "--domain", default="discord.com")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument(
        "--common",
        action="store_true",
        help="Include common_tcp intersection (slow on large DB)",
    )
    p.add_argument(
        "-o",
        "--output",
        default=None,
        help=f"Output JSON (default: {DEFAULT_SHORTLIST_DIR}/shortlist.json)",
    )
    args = p.parse_args(argv)

    import asyncio

    out_default = str(DEFAULT_SHORTLIST_DIR / "shortlist.json")
    output = args.output or out_default
    payload = asyncio.run(
        export_shortlist_json(
            db_path=args.db,
            domains_file=args.domains_file,
            domain=args.domain,
            limit=args.limit,
            output=output,
            include_common=args.common,
        )
    )
    print(f"Wrote {output} ({len(payload.get('tcp', []))} tcp, schema={payload['schema']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
