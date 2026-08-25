"""Age/count retention for debug logs, summaries, harvest, zapret2-dl, voice caches.

Default is collect-only (dry-run). Never deletes week_cov* campaign artifacts.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from blockchecks.engine.paths import CACHE_DIR, DATA_DIR, DEFAULT_OUT_DIR, RUNTIME_LOGS_DIR

log = logging.getLogger(__name__)

NFQWS2_LOG_KEEP = 50
DEFAULT_MAX_AGE_DAYS = 14
_PROTECTED_SUBSTR = ("week_cov",)


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
        log.info("pruned %d nfqws2 debug logs (keep=%d)", len(deleted), keep)
    return deleted


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
    return plan


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
