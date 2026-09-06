"""Age/count retention for debug logs, summaries, harvest, zapret2-dl, voice caches.

Default is collect-only (dry-run). Never deletes week_cov* campaign artifacts.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from blockchecks.engine.paths import (
    CACHE_DIR,
    DATA_DIR,
    DEFAULT_DB_PATH,
    DEFAULT_OUT_DIR,
    RUN_LOCK_FILE,
    RUNTIME_LOGS_DIR,
    STATE_DIR,
)

log = logging.getLogger(__name__)

NFQWS2_LOG_KEEP = 50
DEFAULT_MAX_AGE_DAYS = 14
_PROTECTED_SUBSTR = ("week_cov",)
_TMP_DIR = Path("/tmp")
_SHM_BLOCKCHECKS = Path("/dev/shm/blockchecks")
_TMP_NFQWS2_GLOBS = (
    "bs_nfq_*.conf",
    "bs_hostlist_*",
    "bs_nfqws2_*.conf",
    "bs_discover_udp_*",
)


@dataclass
class GcItem:
    path: Path
    bytes: int
    reason: str


@dataclass
class GcPlan:
    deletes: list[GcItem] = field(default_factory=list)
    skipped: list[GcItem] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(i.bytes for i in self.deletes)


@dataclass
class DbGcStats:
    tcp_rows: int = 0
    udp_rows: int = 0
    orphan_strategies: int = 0
    skipped_lock: bool = False
    dry_run: bool = True
    db_path: Path | None = None


def _sz(path: Path) -> int:
    try:
        if path.is_file():
            return path.stat().st_size
        if path.is_dir():
            return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())
    except OSError:
        return 0
    return 0


def _protected(path: Path) -> bool:
    text = str(path)
    return any(tok in text for tok in _PROTECTED_SUBSTR)


def _age_ok(path: Path, max_age_days: float) -> bool:
    if max_age_days <= 0:
        return True
    try:
        age = time.time() - path.stat().st_mtime
    except OSError:
        return False
    return age >= max_age_days * 86400


def prune_nfqws2_debug_logs(log_dir: Path | None = None, keep: int = NFQWS2_LOG_KEEP) -> list[Path]:
    """Keep the newest *keep* ``nfqws2_*.log`` files; delete the rest.

    Called when a new debug log is created. Never raises.
    """
    directory = log_dir if log_dir is not None else RUNTIME_LOGS_DIR
    try:
        files = sorted(
            (p for p in directory.glob("nfqws2_*.log") if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    except OSError as exc:
        log.warning("nfqws2 log prune listing failed (%s): %s", directory, exc)
        return []
    extra = files[max(0, int(keep)) :]
    deleted: list[Path] = []
    for p in extra:
        if _protected(p):
            continue
        try:
            p.unlink()
            deleted.append(p)
        except OSError as exc:
            log.warning("nfqws2 log unlink failed (%s): %s", p, exc)
    if deleted:
        log.debug("pruned %d nfqws2 debug logs (keep=%d)", len(deleted), keep)
    return deleted


def _has_live_run_lock() -> bool:
    """True when campaign run.lock exists. File-only — do not import service (archrule)."""
    return RUN_LOCK_FILE.is_file()


def _scan_tmp_nfqws2_artifacts(add, *, max_age_days: float) -> None:
    if not _TMP_DIR.is_dir():
        return
    for pattern in _TMP_NFQWS2_GLOBS:
        for p in _TMP_DIR.glob(pattern):
            if p.is_file() and _age_ok(p, max_age_days):
                add(p, "tmp_nfqws2_artifact")


def _scan_shm_staging(add, *, max_age_days: float, live_run: bool) -> None:
    if live_run or not _SHM_BLOCKCHECKS.is_dir():
        return
    for p in _SHM_BLOCKCHECKS.rglob(".staging.*"):
        if p.is_dir() and _age_ok(p, max_age_days):
            add(p, "shm_staging_age")


def _scan_jsonl_old(add, logs_dir: Path) -> None:
    if not logs_dir.is_dir():
        return
    for p in logs_dir.glob("*.jsonl.old"):
        if p.is_file():
            add(p, "events_live_old")


def _scan_sqlite_wal_shm(add, roots: list[Path], *, max_age_days: float) -> None:
    for root in roots:
        if not root.is_dir():
            continue
        for pattern in ("*.db-wal", "*.db-shm", "*-wal", "*-shm"):
            for p in root.glob(pattern):
                if not p.is_file() or not _age_ok(p, max_age_days):
                    continue
                reason = "sqlite_wal" if p.name.endswith("-wal") else "sqlite_shm"
                add(p, reason)


def _scan_log_root(
    root: Path,
    *,
    add,
    max_age_days: float,
    nfqws2_keep: int,
) -> None:
    if not root.is_dir():
        return
    logs = sorted(
        (p for p in root.glob("nfqws2_*.log") if p.is_file()),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )
    for p in logs[max(0, int(nfqws2_keep)) :]:
        add(p, "nfqws2_log_over_keep")
    for p in root.glob("run_summary_*.json"):
        if p.is_file() and _age_ok(p, max_age_days):
            add(p, "run_summary_age")
    harvest_root = root / "harvest" if root.name != "harvest" else root
    if harvest_root.is_dir():
        for p in harvest_root.glob("harvest_*"):
            if p.is_dir() and _age_ok(p, max_age_days):
                add(p, "harvest_dir_age")
    for p in root.glob("nfqws2_*_*.conf"):
        if p.is_file() and _age_ok(p, max_age_days):
            add(p, "export_conf_age")


def collect_gc(
    *,
    max_age_days: float = DEFAULT_MAX_AGE_DAYS,
    nfqws2_keep: int = NFQWS2_LOG_KEEP,
    roots: list[Path] | None = None,
) -> GcPlan:
    """Build a deletion plan. Does not touch disk beyond stat/list."""
    plan = GcPlan()
    extra: list[Path] = []
    if roots is None:
        from blockchecks.engine.config import PROJECT_DIR

        extra = [Path(PROJECT_DIR) / "logs"]
    search = roots if roots is not None else [
        RUNTIME_LOGS_DIR,
        DEFAULT_OUT_DIR,
        CACHE_DIR,
        DATA_DIR,
        *extra,
    ]
    seen: set[Path] = set()

    def _add(path: Path, reason: str, *, force: bool = False) -> None:
        try:
            resolved = path.resolve()
        except OSError:
            return
        if resolved in seen:
            return
        seen.add(resolved)
        if not path.exists():
            return
        item = GcItem(path=path, bytes=_sz(path), reason=reason)
        if _protected(path) and not force:
            plan.skipped.append(item)
            return
        plan.deletes.append(item)

    for root in search:
        _scan_log_root(root, add=_add, max_age_days=max_age_days, nfqws2_keep=nfqws2_keep)

    dl = CACHE_DIR / "zapret2-dl"
    if dl.is_dir():
        tars = sorted(
            (p for p in dl.glob("*.tar.gz") if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for p in tars[1:]:
            if _age_ok(p, max_age_days):
                _add(p, "zapret2_dl_old")
    for p in CACHE_DIR.glob("bs_voice_cache_old_*"):
        if p.is_file() and _age_ok(p, max_age_days):
            _add(p, "voice_cache_old")

    live_run = _has_live_run_lock()
    _scan_tmp_nfqws2_artifacts(_add, max_age_days=max_age_days)
    _scan_shm_staging(_add, max_age_days=max_age_days, live_run=live_run)
    _scan_jsonl_old(_add, RUNTIME_LOGS_DIR)
    wal_roots = list(dict.fromkeys([STATE_DIR, DATA_DIR, *search]))
    _scan_sqlite_wal_shm(_add, wal_roots, max_age_days=max_age_days)
    return plan


# Prefer epoch_ms; fall back to lexicographic ISO timestamp (store format %Y-%m-%dT%H:%M:%S).
_RESULT_AGE_SQL = """(
  (epoch_ms IS NOT NULL AND epoch_ms < :cutoff_ms)
  OR (
    epoch_ms IS NULL
    AND timestamp IS NOT NULL
    AND timestamp != ''
    AND timestamp < :cutoff_iso
  )
)"""
_TCP_COUNT_SQL = f"SELECT COUNT(*) FROM tcp_results WHERE {_RESULT_AGE_SQL}"
_UDP_COUNT_SQL = f"SELECT COUNT(*) FROM udp_results WHERE {_RESULT_AGE_SQL}"
_TCP_DELETE_SQL = f"DELETE FROM tcp_results WHERE {_RESULT_AGE_SQL}"
_UDP_DELETE_SQL = f"DELETE FROM udp_results WHERE {_RESULT_AGE_SQL}"
_KEEP_TCP_SQL = (
    f"SELECT 1 FROM tcp_results t WHERE t.strategy_id = s.id AND NOT {_RESULT_AGE_SQL}"
)
_KEEP_UDP_SQL = (
    f"SELECT 1 FROM udp_results u WHERE u.strategy_id = s.id AND NOT {_RESULT_AGE_SQL}"
)
_ORPHAN_DELETE_SQL = """
DELETE FROM strategies WHERE id NOT IN (
  SELECT strategy_id FROM tcp_results WHERE strategy_id IS NOT NULL
  UNION
  SELECT strategy_id FROM udp_results WHERE strategy_id IS NOT NULL
)
"""


def _sqlite_tables(con: sqlite3.Connection) -> set[str]:
    rows = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'",
    ).fetchall()
    return {str(r[0]) for r in rows}


def _age_cutoffs(max_age_days: float) -> dict[str, int | str]:
    age_s = 0.0 if max_age_days <= 0 else float(max_age_days) * 86400.0
    cutoff = time.time() - age_s
    return {
        "cutoff_ms": int(cutoff * 1000),
        "cutoff_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(cutoff)),
    }


def _count_sql(con: sqlite3.Connection, sql: str, params: dict[str, int | str]) -> int:
    row = con.execute(sql, params).fetchone()
    return int(row[0] if row else 0)


def _count_orphan_strategies(
    con: sqlite3.Connection,
    tables: set[str],
    params: dict[str, int | str],
) -> int:
    """Strategies that would have no tcp/udp rows after aged-result deletion."""
    if "strategies" not in tables:
        return 0
    keep_tcp = _KEEP_TCP_SQL if "tcp_results" in tables else "SELECT 1 WHERE 0"
    keep_udp = _KEEP_UDP_SQL if "udp_results" in tables else "SELECT 1 WHERE 0"
    sql = (
        "SELECT COUNT(*) FROM strategies s "
        f"WHERE NOT EXISTS ({keep_tcp}) AND NOT EXISTS ({keep_udp})"
    )
    return _count_sql(con, sql, params)


def prune_db_results(
    db_path: Path | str | None = None,
    *,
    max_age_days: float,
    dry_run: bool = True,
    orphan_strategies: bool = False,
    live_run: bool | None = None,
) -> DbGcStats:
    """Age-prune tcp_results/udp_results. Never DELETE while run.lock is held.

    Default is count-only (dry_run). ``orphan_strategies`` also drops strategy
    rows that would have no remaining tcp/udp results.
    """
    path = Path(db_path) if db_path is not None else Path(DEFAULT_DB_PATH)
    stats = DbGcStats(dry_run=dry_run, db_path=path)
    if not path.is_file():
        log.warning("gc db: skip, no sqlite file (%s)", path)
        return stats
    locked = _has_live_run_lock() if live_run is None else bool(live_run)
    params = _age_cutoffs(max_age_days)
    try:
        with sqlite3.connect(str(path)) as con:
            tables = _sqlite_tables(con)
            if "tcp_results" in tables:
                stats.tcp_rows = _count_sql(con, _TCP_COUNT_SQL, params)
            if "udp_results" in tables:
                stats.udp_rows = _count_sql(con, _UDP_COUNT_SQL, params)
            if orphan_strategies:
                stats.orphan_strategies = _count_orphan_strategies(con, tables, params)
            if locked and not dry_run:
                stats.skipped_lock = True
                log.warning(
                    "gc db: run.lock held, skipping DELETE "
                    "(tcp_results=%d udp_results=%d orphan_strategies=%d) path=%s",
                    stats.tcp_rows,
                    stats.udp_rows,
                    stats.orphan_strategies,
                    path,
                )
            elif dry_run:
                log.info(
                    "gc db dry-run: tcp_results=%d udp_results=%d orphan_strategies=%d "
                    "(no deletes) path=%s",
                    stats.tcp_rows,
                    stats.udp_rows,
                    stats.orphan_strategies,
                    path,
                )
            else:
                if "tcp_results" in tables and stats.tcp_rows:
                    con.execute(_TCP_DELETE_SQL, params)
                if "udp_results" in tables and stats.udp_rows:
                    con.execute(_UDP_DELETE_SQL, params)
                if orphan_strategies and stats.orphan_strategies and "strategies" in tables:
                    con.execute(_ORPHAN_DELETE_SQL)
                log.info(
                    "gc db deleted: tcp_results=%d udp_results=%d orphan_strategies=%d path=%s",
                    stats.tcp_rows,
                    stats.udp_rows,
                    stats.orphan_strategies,
                    path,
                )
    except sqlite3.Error as exc:
        log.warning("gc db prune failed (%s): %s", path, exc)
    return stats


def apply_gc(plan: GcPlan, *, dry_run: bool = True) -> int:
    """Delete plan.deletes unless dry_run. Returns number of paths removed."""
    if dry_run:
        log.info("gc dry-run: %d paths, %d bytes (no deletes)", len(plan.deletes), plan.total_bytes)
        return 0
    n = 0
    for item in plan.deletes:
        try:
            if item.path.is_dir():
                import shutil

                shutil.rmtree(item.path)
            else:
                item.path.unlink()
            n += 1
        except OSError as exc:
            log.warning("gc unlink failed (%s): %s", item.path, exc)
    log.info("gc removed %d paths (%d bytes)", n, plan.total_bytes)
    return n
