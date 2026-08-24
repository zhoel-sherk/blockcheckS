"""Live per-probe journal + current-probe heartbeat for running campaigns.

Two small files under the XDG state logs dir:

* ``events_live.jsonl`` — one JSON line per finished probe
  ``{ts, domain, strategy, ns, backend, status, http, ms, applied}``.
  Written by the batch/classic probe loops so a campaign can be watched
  physically in real time: ``tail -f`` or MCP ``get_live_events``.
* ``current_probe.json`` — what is being probed right now (atomic rename),
  surfaced via MCP ``get_series_status`` → ``live``.

Rotation: when the journal exceeds ~32 MB it is replaced with a fresh file
(previous content dropped — this is a live-view channel, not an archive;
durable results live in state.db).
"""

from __future__ import annotations

import json
import os
import time

from blockchecks.engine.paths import RUNTIME_LOGS_DIR

EVENTS_FILE = RUNTIME_LOGS_DIR / "events_live.jsonl"
CURRENT_FILE = RUNTIME_LOGS_DIR / "current_probe.json"

_MAX_JOURNAL_BYTES = 32 * 1024 * 1024


def _rotate_if_needed() -> None:
    try:
        if EVENTS_FILE.is_file() and EVENTS_FILE.stat().st_size > _MAX_JOURNAL_BYTES:
            EVENTS_FILE.replace(EVENTS_FILE.with_suffix(".jsonl.old"))
    except OSError:
        pass


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
    try:
        RUNTIME_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        _rotate_if_needed()
        with EVENTS_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


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
    tmp = CURRENT_FILE.with_suffix(".tmp")
    try:
        RUNTIME_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, CURRENT_FILE)
    except OSError:
        pass


def read_current() -> dict | None:
    """Current probe snapshot for API consumers (None if absent/stale file)."""
    try:
        return json.loads(CURRENT_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def tail_events(limit: int = 50, domain: str | None = None) -> list[dict]:
    """Last *limit* probe records, newest last; optional exact-domain filter."""
    try:
        with EVENTS_FILE.open("r", encoding="utf-8") as fh:
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
