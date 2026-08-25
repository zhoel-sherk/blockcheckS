"""Harvest candidate strategies from a state DB for external validation.

Кандидатная выборка «стратегия → домены» для валидатора (dpi-tester):
batch.txt формата run_batch() («домены,csv | стратегия»), JSON-манифест
blockchecks.harvest/v1 и опциональные самодостаточные raw-конфы на кандидата
(--write-confs, Tier-2 для финалистов).

Шов для будущего переезда выборки в GP-access-control-plane: ядро pure и
read-only (stdlib sqlite3, mode=ro), без новых зависимостей.

Saturation-метрика: если почти все топ-кандидаты проходят домен, пробы там
не различают стратегии («лёгкий»/насыщенный домен — ценен для конфига,
шумен для ранжирования). Домены с pass_share >= 0.85 помечаются saturated.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from blockchecks.engine.blob_aliases import (
    apply_blob_renames,
    extract_blob_names,
    safe_blob_name,
)
from blockchecks.engine.conf_builder import (
    build_raw_conf,
    filter_export_strategies,
    looks_like_conf_path,
    lua_desync_cores_from_conf,
    write_export_bundle,
)
from blockchecks.engine.paths import DEFAULT_DB_PATH

log = logging.getLogger("blockchecks.harvest_batch")

SCHEMA = "blockchecks.harvest/v1"
SATURATED_SHARE = 0.85


@dataclass
class HarvestCandidate:
    strategy: str
    domains: list[str]
    coverage: int
    avg_latency_ms: float
    attempts: int = 0
    pass_rate: float = 1.0
    conf_path: str | None = None  # непусто, если стратегия развёрнута из .conf


@dataclass
class HarvestResult:
    candidates: list[HarvestCandidate]
    domains_meta: list[dict[str, Any]] = field(default_factory=list)
    quarantined_excluded: list[str] = field(default_factory=list)
    skipped_unresolved: int = 0


def _connect_ro(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"state DB not found: {path}")
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def _resolve_strategy_string(config_path: str) -> str | None:
    """config_path → строка --lua-desync-ядра; .conf-пути разворачиваются.

    Blob-идентификаторы с ведущей цифрой переименовываются (4pda→b4pda),
    как в конф-генераторах — nfqws2 фатально падает на 'bad identifier'.
    """
    text = (config_path or "").strip()
    if not text:
        return None
    if looks_like_conf_path(text):
        strat = next(iter(filter_export_strategies(
            [c for c in lua_desync_cores_from_conf(text) if c]
        )), None)
    else:
        strat = text
    if not strat:
        return None
    # переименование ДО валидации: цифро-ведущий blob сам по себе не повод
    # отбрасывать рабочую стратегию (nfqws2-совместимое имя = b<name>)
    renames = {
        name: safe_blob_name(name) for name in extract_blob_names(strat)
        if name != safe_blob_name(name)
    }
    if renames:
        strat = apply_blob_renames(strat, renames)
    kept = filter_export_strategies([strat])
    return kept[0] if kept else None


def collect_harvest_candidates(
    db_path: str | Path = DEFAULT_DB_PATH,
    *,
    proto: str = "tcp",
    top: int = 20,
    min_domains: int = 2,
    statuses: Iterable[str] = ("PASS", "THROTTLED"),
) -> HarvestResult:
    """Latest row per strategy×domain → сгруппированные кандидаты.

    Ранжирование: покрытие (число доменов) ↓, avg latency ↑ — как в
    generate_router_config. Карантинные домены исключаются целиком.
    """
    status_list = [s.upper() for s in statuses] or ["PASS"]
    placeholders = ",".join("?" for _ in status_list)
    conn = _connect_ro(db_path)
    try:
        quarantined = {
            r["domain"]
            for r in conn.execute("SELECT domain FROM quarantined").fetchall()
            if r["domain"]
        }
        rows = conn.execute(
            f"""
            WITH latest AS (
                SELECT t.strategy_id, t.domain, t.status, t.latency_ms,
                       ROW_NUMBER() OVER (
                           PARTITION BY t.strategy_id, t.domain ORDER BY t.id DESC
                       ) AS rn
                FROM tcp_results t
                JOIN strategies s ON s.id = t.strategy_id
                WHERE s.proto = ?
            )
            SELECT l.strategy_id AS sid, s.name AS name, s.config_path AS config_path,
                   l.domain AS domain, l.status AS status, l.latency_ms AS latency_ms
            FROM latest l
            JOIN strategies s ON s.id = l.strategy_id
            WHERE l.rn = 1 AND l.status IN ({placeholders})
              AND l.domain NOT IN
                  (SELECT domain FROM quarantined WHERE domain IS NOT NULL)
            """,
            (proto, *status_list),
        ).fetchall()
    finally:
        conn.close()

    grouped: dict[int, dict[str, Any]] = {}
    for r in rows:
        g = grouped.setdefault(
            r["sid"],
            {"name": r["name"], "config_path": r["config_path"], "domains": [],
             "lat_sum": 0.0, "lat_n": 0},
        )
        g["domains"].append(r["domain"])
        if r["latency_ms"] is not None:
            g["lat_sum"] += float(r["latency_ms"])
            g["lat_n"] += 1

    skipped = 0
    cands: list[HarvestCandidate] = []
    for g in grouped.values():
        if len(g["domains"]) < min_domains:
            continue
        strat = _resolve_strategy_string(g["config_path"] or "")
        if not strat:
            skipped += 1
            continue
        lat_n = max(1, g["lat_n"])
        from_conf = bool(looks_like_conf_path((g["config_path"] or "").strip()))
        cands.append(
            HarvestCandidate(
                strategy=strat,
                domains=sorted(g["domains"]),
                coverage=len(g["domains"]),
                avg_latency_ms=round(g["lat_sum"] / lat_n, 1),
                attempts=len(g["domains"]),
                pass_rate=1.0,
                conf_path=g["config_path"] if from_conf else None,
            )
        )

    cands.sort(key=lambda c: (-c.coverage, c.avg_latency_ms))
    total_before_top = len(cands)
    cands = cands[:max(1, top)]

    share: dict[str, int] = {}
    for c in cands:
        for d in c.domains:
            share[d] = share.get(d, 0) + 1
    domains_meta = [
        {
            "domain": d,
            "pass_share": round(n / len(cands), 2) if cands else 0.0,
            "saturated": bool(cands) and n / len(cands) >= SATURATED_SHARE,
        }
        for d, n in sorted(share.items(), key=lambda kv: -kv[1])
    ]
    log.info(
        "%s",
        f"harvest: {len(cands)} candidates "
        f"(of {total_before_top} with >={min_domains} domains), "
        f"{skipped} unresolved, {len(quarantined)} quarantined excluded",
    )
    return HarvestResult(
        candidates=cands,
        domains_meta=domains_meta,
        quarantined_excluded=sorted(quarantined),
        skipped_unresolved=skipped,
    )


def render_batch_txt(result: HarvestResult) -> str:
    """Строки «dom1,dom2 | стратегия» — вход dpi-tester run_batch()."""
    lines = []
    for c in result.candidates:
        lines.append(f"{','.join(c.domains)} | {c.strategy}")
    return "\n".join(lines) + ("\n" if lines else "")


def build_manifest(result: HarvestResult, *, db_path: str | Path, proto: str,
                   top: int, min_domains: int) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_db": Path(db_path).name,
        "proto": proto,
        "params": {"top": top, "min_domains": min_domains},
        "candidates": [asdict(c) for c in result.candidates],
        "domains_meta": result.domains_meta,
        "quarantined_excluded": result.quarantined_excluded,
        "skipped_unresolved": result.skipped_unresolved,
    }


def _safe_name(idx: int, strategy: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9]+", "_", strategy)[:48].strip("_") or "cand"
    return f"{idx:02d}_{stem}"


def write_confs(result: HarvestResult, out_dir: str | Path) -> list[Path]:
    """Самодостаточный raw @file + blobs/lua на каждого кандидата (Tier-2)."""
    written: list[Path] = []
    root = Path(out_dir).expanduser()
    for i, c in enumerate(result.candidates):
        text = build_raw_conf(
            tcp_strategies=[c.strategy], udp_strategies=[], quic_strategies=None,
            domains=c.domains, comment=f"harvest candidate {i} ({c.coverage} domains)",
        )
        bundle_dir = root / _safe_name(i, c.strategy)
        write_export_bundle(text, bundle_dir, tcp_strats=[c.strategy])
        written.append(bundle_dir)
    return written


__all__ = [
    "SCHEMA",
    "SATURATED_SHARE",
    "HarvestCandidate",
    "HarvestResult",
    "build_manifest",
    "collect_harvest_candidates",
    "render_batch_txt",
    "write_confs",
]
