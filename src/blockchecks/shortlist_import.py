"""Import blockchecks.shortlist/v1 into presets and optional state.db seed (P5-1)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from blockchecks.engine.store import open_run_store
from blockchecks.provider_import import DEFAULT_PRESETS_DIR, write_shortlist_presets

SCHEMA = "blockchecks.shortlist/v1"


def load_shortlist(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("shortlist must be a JSON object")
    schema = data.get("schema", "")
    if schema and schema != SCHEMA:
        raise ValueError(f"unsupported schema: {schema!r} (expected {SCHEMA})")
    return data


def shortlist_to_provider_summary(shortlist: dict[str, Any]) -> dict[str, Any]:
    """Convert shortlist v1 → provider_import-compatible summary."""
    custom: dict[str, list[str]] = {}
    for proto_key, bucket_key in (("tcp", "tcp"), ("udp", "udp"), ("quic", "quic")):
        rows = shortlist.get(bucket_key) or []
        if not isinstance(rows, list):
            continue
        lines: list[str] = []
        for row in rows:
            if isinstance(row, dict):
                strat = str(row.get("strategy", "")).strip()
                if strat:
                    lines.append(strat)
            elif isinstance(row, str) and row.strip():
                lines.append(row.strip())
        if lines:
            custom[proto_key if proto_key != "tcp" else "tls12"] = lines

    shortlist_map: dict[str, dict[str, str]] = {}
    for row in shortlist.get("common_tcp") or []:
        if not isinstance(row, dict):
            continue
        strat = str(row.get("strategy", "")).strip()
        if not strat:
            continue
        for dom in row.get("domains_pass") or shortlist.get("domains") or ["*"]:
            shortlist_map.setdefault(str(dom), {})["tls12"] = strat

    return {
        "provider_id": f"shortlist:{shortlist.get('source_db', 'import')}",
        "generated_at": shortlist.get("generated_at", ""),
        "custom_strategies": custom,
        "shortlist": shortlist_map,
    }


async def seed_state_db(
    shortlist: dict[str, Any],
    db_path: str,
    *,
    mark_pass: bool = True,
) -> int:
    """Seed strategies + optional PASS rows for resume."""
    if not mark_pass:
        return 0
    db = open_run_store(db_path)
    await db.init()
    count = 0
    domains = shortlist.get("domains") or ["discord.com"]
    primary = domains[0]

    for row in shortlist.get("tcp") or []:
        if not isinstance(row, dict):
            continue
        label = str(row.get("label") or f"import_tcp_{count}")
        strat = str(row.get("strategy", "")).strip()
        if not strat:
            continue
        pass_domains = row.get("domains_pass") or [primary]
        for dom in pass_domains:
            await db.log_tcp(
                label,
                dom,
                "PASS",
                float(row.get("avg_latency_ms") or row.get("latency_ms") or 0.0),
                200,
                config_path=strat,
            )
            count += 1

    for row in shortlist.get("udp") or []:
        if not isinstance(row, dict):
            continue
        label = str(row.get("label") or f"import_udp_{count}")
        strat = str(row.get("strategy", "")).strip()
        if not strat:
            continue
        target = str(row.get("target") or "voice")
        await db.log_udp(
            label,
            target,
            "PASS",
            float(row.get("latency_ms") or 0.0),
            config_path=strat,
        )
        count += 1

    for row in shortlist.get("quic") or []:
        if not isinstance(row, dict):
            continue
        label = str(row.get("label") or f"import_quic_{count}")
        strat = str(row.get("strategy", "")).strip()
        if not strat:
            continue
        pass_domains = row.get("domains_pass") or [primary]
        for dom in pass_domains:
            await db.log_tcp(
                label,
                dom,
                "PASS",
                float(row.get("latency_ms") or 0.0),
                200,
                config_path=strat,
                proto="quic",
            )
            count += 1

    return count


async def import_shortlist_async(
    path: str | Path,
    *,
    out_dir: str | Path | None = None,
    prefix: str = "shortlist",
    db_path: str | None = None,
    seed_db: bool = False,
) -> dict[str, Any]:
    shortlist = load_shortlist(path)
    summary = shortlist_to_provider_summary(shortlist)
    written = write_shortlist_presets(summary, out_dir or DEFAULT_PRESETS_DIR, prefix=prefix)
    result: dict[str, Any] = {"presets": written, "schema": shortlist.get("schema", SCHEMA)}
    if seed_db and db_path:
        result["seeded_rows"] = await seed_state_db(shortlist, db_path)
    return result


def import_shortlist(
    path: str | Path,
    *,
    out_dir: str | Path | None = None,
    prefix: str = "shortlist",
    db_path: str | None = None,
    seed_db: bool = False,
) -> dict[str, Any]:
    shortlist = load_shortlist(path)
    summary = shortlist_to_provider_summary(shortlist)
    written = write_shortlist_presets(summary, out_dir or DEFAULT_PRESETS_DIR, prefix=prefix)
    result: dict[str, Any] = {"presets": written, "schema": shortlist.get("schema", SCHEMA)}
    if seed_db and db_path:
        import asyncio

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            seeded = asyncio.run(seed_state_db(shortlist, db_path))
            result["seeded_rows"] = seeded
        else:
            # Caller is inside async context — use import_shortlist_async
            raise RuntimeError("use await import_shortlist_async() from async code")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Import blockchecks.shortlist/v1")
    p.add_argument("-i", "--input", required=True, help="Path to shortlist.json")
    p.add_argument("--out-dir", default=None)
    p.add_argument("--prefix", default="shortlist")
    p.add_argument("--db", default=None, help="Seed state.db with PASS rows")
    p.add_argument("--seed-db", action="store_true")
    args = p.parse_args(argv)

    result = import_shortlist(
        args.input,
        out_dir=args.out_dir,
        prefix=args.prefix,
        db_path=args.db,
        seed_db=args.seed_db or bool(args.db),
    )
    print(f"Imported {args.input} (schema={result['schema']})")
    for proto, path in result["presets"].items():
        print(f"  {proto}: {path}")
    if "seeded_rows" in result:
        print(f"  seeded: {result['seeded_rows']} DB rows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
