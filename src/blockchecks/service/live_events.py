"""Live per-probe journal + current-probe heartbeat for running campaigns.

Per-process journal under the XDG state logs dir:

* ``events_live.<pid>.jsonl`` — one JSON line per finished probe
  ``{ts, domain, strategy, ns, backend, status, http, ms, applied}``.
  Legacy ``events_live.jsonl`` remains a reader fallback when no suffixed file
  matches run.lock / newest scan.
* ``current_probe.<pid>.json`` — what is being probed right now (atomic rename),
  surfaced via MCP ``get_series_status`` → ``live``.

Rotation: when the journal exceeds ~32 MB it is replaced with a fresh file
(previous content dropped — this is a live-view channel, not an archive;
durable results live in state.db).
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

from blockchecks.engine.paths import RUNTIME_LOGS_DIR

log = logging.getLogger(__name__)

# Legacy unsuffixed paths (reader fallback; tests may monkeypatch these).
EVENTS_FILE = RUNTIME_LOGS_DIR / "events_live.jsonl"
CURRENT_FILE = RUNTIME_LOGS_DIR / "current_probe.json"

_MAX_JOURNAL_BYTES = 32 * 1024 * 1024


def _events_name(pid: int | str) -> str:
    return f"events_live.{int(pid)}.jsonl"


def _current_name(pid: int | str) -> str:
    return f"current_probe.{int(pid)}.json"


def writer_events_path() -> Path:
    """Journal path for the current writer process."""
    return RUNTIME_LOGS_DIR / _events_name(os.getpid())


def writer_current_path() -> Path:
    """Current-probe snapshot for the current writer process."""
    return RUNTIME_LOGS_DIR / _current_name(os.getpid())


def _suffixed_events_candidates() -> list[Path]:
    if not RUNTIME_LOGS_DIR.is_dir():
        return []
    return [p for p in RUNTIME_LOGS_DIR.glob("events_live.*.jsonl") if p.is_file()]


def latest_events_path() -> Path:
    """Active journal: run.lock pid, else newest suffixed file, else legacy."""
    try:
        from blockchecks.service.run_control import read_active_run

        info = read_active_run()
        if info is not None:
            locked = RUNTIME_LOGS_DIR / _events_name(info.pid)
            if locked.is_file():
                return locked
    except Exception as exc:
        log.warning("latest_events_path run.lock probe failed: %s", exc)

    candidates = _suffixed_events_candidates()
    if candidates:
        return max(candidates, key=lambda p: p.stat().st_mtime)
    if EVENTS_FILE.is_file():
        return EVENTS_FILE
    return writer_events_path()


def latest_current_path() -> Path:
    """Active current-probe file: run.lock pid, else newest suffixed, else legacy."""
    try:
        from blockchecks.service.run_control import read_active_run

        info = read_active_run()
        if info is not None:
            locked = RUNTIME_LOGS_DIR / _current_name(info.pid)
            if locked.is_file():
                return locked
    except Exception as exc:
        log.warning("latest_current_path run.lock probe failed: %s", exc)

    if not RUNTIME_LOGS_DIR.is_dir():
        return CURRENT_FILE
    candidates = [p for p in RUNTIME_LOGS_DIR.glob("current_probe.*.json") if p.is_file()]
    if candidates:
        return max(candidates, key=lambda p: p.stat().st_mtime)
    if CURRENT_FILE.is_file():
        return CURRENT_FILE
    return writer_current_path()


def _rotate_if_needed(path: Path) -> None:
    try:
        if path.is_file() and path.stat().st_size > _MAX_JOURNAL_BYTES:
            path.replace(path.with_name(path.name + ".old"))
    except OSError as exc:
        log.warning("live_events rotate failed (%s): %s", path, exc)


def _safe_int(v) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _safe_float(v) -> float:
    try:
        return float(v or 0.0)
    except (TypeError, ValueError):
        return 0.0


def write_probe(
    *,
    domain: str,
    strategy: str,
    ns: str,
    backend: str,
    status: str,
    http_code: int = 0,
    latency_ms: float = 0,
    applied: bool | None = None,
) -> None:
    """Append one finished-probe record (best-effort, never raises)."""
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "domain": domain,
        "strategy": (strategy or "")[:64],
        "ns": ns,
        "backend": backend,
        "status": status,
        "http": _safe_int(http_code),
        "ms": round(_safe_float(latency_ms)),
        "applied": applied if isinstance(applied, bool) else None,
    }
    path = writer_events_path()
    try:
        RUNTIME_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        _rotate_if_needed(path)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as exc:
        log.warning("live_events write_probe failed: %s", exc)


def set_current(*, domain: str, strategy: str, ns: str, backend: str) -> None:
    """Atomically publish 'what is being probed right now'."""
    payload = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "epoch": int(time.time()),
        "domain": domain,
        "strategy": (strategy or "")[:96],
        "ns": ns,
        "backend": backend,
    }
    path = writer_current_path()
    tmp = path.with_suffix(".tmp")
    try:
        RUNTIME_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        log.warning("live_events set_current failed: %s", exc)


def read_current() -> dict | None:
    """Current probe snapshot for API consumers (None if absent/stale file)."""
    path = latest_current_path()
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def tail_events(limit: int = 50, domain: str | None = None) -> list[dict]:
    """Last *limit* probe records, newest last; optional exact-domain filter."""
    path = latest_events_path()
    try:
        with path.open("r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out: list[dict] = []
    for ln in reversed(lines):
        ln = ln.strip()
        if not ln:
            continue
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue  # torn line across a truncate boundary — skip silently
        if domain and rec.get("domain") != domain:
            continue
        out.append(rec)
        if len(out) >= max(1, int(limit)):
            break
    out.reverse()
    return out
