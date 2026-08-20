"""Import provider_summary.json into presets / user matrix."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


DEFAULT_PRESETS_DIR = Path(__file__).resolve().parents[2] / "presets" / "strategies"


def load_provider_summary(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("provider_summary must be a JSON object")
    return data


def _normalize_strategy(line: str) -> str:
    """Strip nfqws2 CLI prefix; keep lua-desync cores only."""
    line = line.strip()
    if not line or line.startswith("#"):
        return ""
    if "--lua-desync=" in line:
        return line.split("--lua-desync=", 1)[1].strip()
    if line.startswith("--"):
        return ""
    return line


def extract_strategies(summary: dict[str, Any]) -> dict[str, list[str]]:
    """Return proto -> unique strategy strings."""
    out: dict[str, list[str]] = {}
    custom = summary.get("custom_strategies") or {}
    if isinstance(custom, dict):
        for proto, lines in custom.items():
            if not isinstance(lines, list):
                continue
            seen: set[str] = set()
            bucket: list[str] = []
            for raw in lines:
                s = _normalize_strategy(str(raw))
                if s and s not in seen:
                    seen.add(s)
                    bucket.append(s)
            if bucket:
                out[proto] = bucket

    shortlist = summary.get("shortlist") or {}
    if isinstance(shortlist, dict):
        for _domain, profiles in shortlist.items():
            if not isinstance(profiles, dict):
                continue
            for proto, strat in profiles.items():
                s = _normalize_strategy(str(strat))
                if not s:
                    continue
                bucket = out.setdefault(proto, [])
                if s not in bucket:
                    bucket.append(s)
    return out


def write_shortlist_presets(
    summary: dict[str, Any],
    out_dir: str | Path | None = None,
    *,
    prefix: str = "provider",
) -> dict[str, str]:
    """Write per-protocol .tls/.quic preset files from summary."""
    out_dir = Path(out_dir or DEFAULT_PRESETS_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    strategies = extract_strategies(summary)
    written: dict[str, str] = {}
    ext_map = {"quic": "quic", "udp_voice": "udp", "http": "http"}
    for proto, lines in strategies.items():
        ext = ext_map.get(proto, "tls")
        path = out_dir / f"{prefix}-{proto}.{ext}"
        header = [
            f"# Imported from provider_summary ({summary.get('provider_id', 'unknown')})",
            f"# generated_at: {summary.get('generated_at', '')}",
            "",
        ]
        path.write_text("\n".join(header + lines) + "\n", encoding="utf-8")
        written[proto] = str(path)
    return written


def merge_into_user_matrix(
    summary_path: str | Path,
    matrix_path: str | Path,
    *,
    append: bool = True,
) -> str:
    """Merge provider strategies into a user-matrix file for `bs scan --user-matrix`."""
    summary = load_provider_summary(summary_path)
    strategies = extract_strategies(summary)
    lines: list[str] = []
    if append and os.path.isfile(matrix_path):
        lines = Path(matrix_path).read_text(encoding="utf-8").splitlines()

    existing = {ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")}
    for proto in ("tls12", "tls13", "http", "quic", "udp_voice"):
        for s in strategies.get(proto, []):
            if s not in existing:
                lines.append(s)
                existing.add(s)

    Path(matrix_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(matrix_path)


def provider_summary_to_shortlist(summary: dict[str, Any]) -> dict[str, Any]:
    """Convert provider_summary.json → shortlist v1 shape for ``seed_state_db``."""
    strategies = extract_strategies(summary)
    domains: list[str] = []
    shortlist_map = summary.get("shortlist") or {}
    if isinstance(shortlist_map, dict):
        domains = [str(d) for d in shortlist_map if d and d != "*"]
    if not domains:
        domains = ["discord.com"]

    tcp_rows: list[dict[str, Any]] = []
    for proto in ("tls12", "tls13", "tcp"):
        for i, strat in enumerate(strategies.get(proto, [])):
            tcp_rows.append(
                {
                    "label": f"provider_{proto}_{i}",
                    "strategy": strat,
                    "domains_pass": domains,
                    "latency_ms": 0.0,
                }
            )

    udp_rows: list[dict[str, Any]] = []
    for i, strat in enumerate(strategies.get("udp_voice", []) + strategies.get("udp", [])):
        udp_rows.append(
            {
                "label": f"provider_udp_{i}",
                "strategy": strat,
                "target": "voice",
                "latency_ms": 0.0,
            }
        )

    quic_rows: list[dict[str, Any]] = []
    for i, strat in enumerate(strategies.get("quic", [])):
        quic_rows.append(
            {
                "label": f"provider_quic_{i}",
                "strategy": strat,
                "domains_pass": domains,
                "latency_ms": 0.0,
            }
        )

    return {
        "schema": "blockchecks.shortlist/v1",
        "source_db": f"provider:{summary.get('provider_id', 'import')}",
        "generated_at": summary.get("generated_at", ""),
        "domains": domains,
        "tcp": tcp_rows,
        "udp": udp_rows,
        "quic": quic_rows,
        "common_tcp": [],
    }


def build_import_report(summary: dict[str, Any]) -> str:
    strategies = extract_strategies(summary)
    lines = [
        f"provider_id: {summary.get('provider_id', '?')}",
        f"generated_at: {summary.get('generated_at', '?')}",
        f"dns_tampering: {(summary.get('dns') or {}).get('tampered_count', '?')}",
    ]
    for proto, bucket in sorted(strategies.items()):
        lines.append(f"  {proto}: {len(bucket)} strategies")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Import provider_summary.json into BS presets")
    p.add_argument("--summary", "-i", required=True, help="Path to provider_summary.json")
    p.add_argument(
        "--out-dir",
        default=None,
        help="Presets output dir (default: presets/strategies/)",
    )
    p.add_argument(
        "--merge-matrix",
        default=None,
        help="Append strategies to user-matrix file (for bs scan --user-matrix)",
    )
    p.add_argument("--prefix", default="provider", help="Preset filename prefix")
    p.add_argument(
        "--seed-db",
        default=None,
        metavar="PATH",
        help="Seed state.db PASS rows from provider strategies (P5-1)",
    )
    args = p.parse_args(argv)

    summary = load_provider_summary(args.summary)
    written = write_shortlist_presets(summary, args.out_dir, prefix=args.prefix)
    log.info("%s", build_import_report(summary))
    log.info("Wrote presets:")
    for proto, path in written.items():
        log.info("%s", f"  {proto}: {path}")

    if args.merge_matrix:
        path = merge_into_user_matrix(args.summary, args.merge_matrix)
        log.info("%s", f"Merged user-matrix: {path}")

    if args.seed_db:
        import asyncio

        from blockchecks.shortlist_import import seed_state_db

        shortlist = provider_summary_to_shortlist(summary)
        seeded = asyncio.run(seed_state_db(shortlist, args.seed_db))
        log.info("%s", f"Seeded {seeded} rows → {args.seed_db}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
