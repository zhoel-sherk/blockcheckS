"""Application logging: operator console + rotating file + debug toggle + log tail."""

from __future__ import annotations

import logging
import logging.handlers
import os
import re
import sys
import threading
from pathlib import Path

from blockchecks.engine.paths import RUNTIME_LOGS_DIR, ensure_dirs, reclaim_sudo_ownership

LOGGER_NAME = "blockchecks"
LOG_SOURCES = frozenset({"python", "campaign", "nfqws2"})
_THIRD_PARTY = ("asyncio", "urllib3", "curl_cffi", "websockets", "aiohttp", "httpx")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_FILE_BYTES = 10 * 1024 * 1024
_FILE_BACKUPS = 3
_FILE_FMT = "%(asctime)s %(levelname)s %(name)s %(message)s"

_saved_python_level: int | None = None
_saved_nfq: str | None = None
_console_stream: str = "stdout"
_pending_debug_toggle = False
_debug_apply_lock = threading.Lock()
_debug_watcher_started = False
_debug_watcher_wake = threading.Event()
_applying_debug_toggle = False


class OperatorFormatter(logging.Formatter):
    """INFO is the raw message (print-compatible). DEBUG gets a short tag."""

    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        if record.levelno == logging.DEBUG:
            return f"[debug] {msg}"
        return msg


class _FlushStreamHandler(logging.StreamHandler):
    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        if record.levelno >= logging.ERROR:
            try:
                self.flush()
            except ValueError:
                pass


class _FlushRotatingFileHandler(logging.handlers.RotatingFileHandler):
    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        if record.levelno >= logging.ERROR:
            self.flush()


class _MaxLevelFilter(logging.Filter):
    def __init__(self, max_level: int) -> None:
        super().__init__()
        self.max_level = max_level

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno <= self.max_level


class _DeferredDebugFilter(logging.Filter):
    """Apply a pending SIGUSR1 debug toggle before each log record is emitted."""

    def filter(self, _record: logging.LogRecord) -> bool:
        if not _applying_debug_toggle:
            apply_pending_debug_toggle()
        return True


def _parse_level(level: str | int | None) -> int:
    if isinstance(level, int):
        return level
    if isinstance(level, str) and level.strip():
        return int(getattr(logging, level.strip().upper(), logging.INFO))
    env = os.environ.get("BLOCKCHECKS_LOG_LEVEL", "").strip()
    if env:
        return int(getattr(logging, env.upper(), logging.INFO))
    return logging.INFO


def toggle_debug_mode() -> dict:
    """Request debug flip from a signal handler (no I/O; applied asynchronously)."""
    global _pending_debug_toggle
    _pending_debug_toggle = True
    _debug_watcher_wake.set()
    return debug_status()


def apply_pending_debug_toggle() -> dict | None:
    """Apply a deferred SIGUSR1 toggle. Safe outside the signal handler."""
    global _pending_debug_toggle, _applying_debug_toggle
    with _debug_apply_lock:
        if not _pending_debug_toggle:
            return None
        _pending_debug_toggle = False
        enabled = not bool(debug_status()["enabled"])
        status = set_debug_mode(enabled)
    _applying_debug_toggle = True
    try:
        on = "ON" if enabled else "OFF"
        logging.getLogger(LOGGER_NAME).info(
            "%s", f"  [debug] SIGUSR1 — debug {on} on next probe"
        )
    finally:
        _applying_debug_toggle = False
    return status


def _debug_toggle_watcher() -> None:
    while True:
        _debug_watcher_wake.wait(timeout=1.0)
        _debug_watcher_wake.clear()
        while apply_pending_debug_toggle() is not None:
            pass


def _ensure_debug_watcher() -> None:
    global _debug_watcher_started
    if _debug_watcher_started:
        return
    with _debug_apply_lock:
        if _debug_watcher_started:
            return
        threading.Thread(
            target=_debug_toggle_watcher,
            name="blockchecks-debug-toggle",
            daemon=True,
        ).start()
        _debug_watcher_started = True


def python_log_path() -> Path:
    return RUNTIME_LOGS_DIR / "blockchecks.log"


def _newest_glob(directory: Path, pattern: str) -> Path | None:
    matches = sorted(directory.glob(pattern), key=lambda p: p.stat().st_mtime if p.is_file() else 0)
    return matches[-1] if matches else None


def campaign_log_path() -> Path | None:
    """Resolve campaign stdout via run_*_LATEST.logpath (cwd/logs, then XDG)."""
    for logs_dir in (Path.cwd() / "logs", RUNTIME_LOGS_DIR):
        ptrs = sorted(logs_dir.glob("run_*_LATEST.logpath"), key=lambda p: p.stat().st_mtime)
        if not ptrs:
            continue
        try:
            target = Path(ptrs[-1].read_text(encoding="utf-8").strip())
        except OSError:
            continue
        if target.is_file():
            return target
    return _newest_glob(Path.cwd() / "logs", "run_*.log") or _newest_glob(
        RUNTIME_LOGS_DIR, "run_*.log"
    )


def nfqws2_log_path() -> Path | None:
    return _newest_glob(RUNTIME_LOGS_DIR, "nfqws2_*.log")


def _path_for_source(source: str) -> Path | None:
    return {
        "python": python_log_path(),
        "campaign": campaign_log_path(),
        "nfqws2": nfqws2_log_path(),
    }.get(source)


def _silence_third_party() -> None:
    for name in _THIRD_PARTY:
        logging.getLogger(name).setLevel(logging.WARNING)


def flush_log_handlers() -> None:
    for handler in logging.getLogger(LOGGER_NAME).handlers:
        handler.flush()


def apply_log_level(level: str | int) -> None:
    log_level = _parse_level(level)
    root = logging.getLogger(LOGGER_NAME)
    root.setLevel(log_level)
    for handler in root.handlers:
        handler.setLevel(log_level)


def configure_logging(
    *,
    level: str | int | None = None,
    console: str = "stdout",
) -> None:
    """Attach rotating file + stream handlers once; always apply *level*."""
    global _console_stream
    _console_stream = console if console == "stderr" else "stdout"
    log_level = _parse_level(level)
    root = logging.getLogger(LOGGER_NAME)
    if root.handlers:
        apply_log_level(log_level)
        _ensure_debug_watcher()
        return
    ensure_dirs()
    _silence_third_party()
    _ensure_debug_watcher()
    root.setLevel(log_level)
    root.propagate = False

    file_fmt = logging.Formatter(_FILE_FMT)
    try:
        RUNTIME_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        path = python_log_path()
        fh = _FlushRotatingFileHandler(
            path, maxBytes=_FILE_BYTES, backupCount=_FILE_BACKUPS, encoding="utf-8"
        )
        fh.setLevel(log_level)
        fh.setFormatter(file_fmt)
        fh.addFilter(_DeferredDebugFilter())
        root.addHandler(fh)
        reclaim_sudo_ownership(path)
    except OSError:
        pass

    op_fmt = OperatorFormatter()
    if _console_stream == "stderr":
        err = _FlushStreamHandler(sys.stderr)
        err.setLevel(log_level)
        err.setFormatter(op_fmt)
        err.addFilter(_DeferredDebugFilter())
        root.addHandler(err)
        return
    out = _FlushStreamHandler(sys.stdout)
    out.setLevel(log_level)
    out.setFormatter(op_fmt)
    out.addFilter(_MaxLevelFilter(logging.INFO))
    out.addFilter(_DeferredDebugFilter())
    root.addHandler(out)
    err = _FlushStreamHandler(sys.stderr)
    err.setLevel(logging.WARNING)
    err.setFormatter(op_fmt)
    err.addFilter(_DeferredDebugFilter())
    root.addHandler(err)


def debug_status() -> dict:
    root = logging.getLogger(LOGGER_NAME)
    nfq = os.environ.get("BLOCKCHECKS_NFQWS2_DEBUG", "").strip()
    level = root.level if root.level else logging.NOTSET
    return {
        "enabled": level <= logging.DEBUG and level != logging.NOTSET,
        "python_level": logging.getLevelName(level),
        "nfqws2_debug": nfq,
        "log_files": {
            "python": str(python_log_path()),
            "nfqws2": str(nfqws2_log_path() or ""),
            "campaign": str(campaign_log_path() or ""),
        },
    }


def set_debug_mode(enabled: bool) -> dict:
    """Toggle Python DEBUG + nfqws2 env; inherit via BLOCKCHECKS_LOG_LEVEL."""
    global _saved_python_level, _saved_nfq
    root = logging.getLogger(LOGGER_NAME)
    if enabled:
        if _saved_python_level is None:
            _saved_python_level = root.level if root.level else logging.INFO
            _saved_nfq = os.environ.get("BLOCKCHECKS_NFQWS2_DEBUG", "")
        os.environ["BLOCKCHECKS_LOG_LEVEL"] = "DEBUG"
        os.environ["BLOCKCHECKS_NFQWS2_DEBUG"] = "1"
        if not root.handlers:
            configure_logging(level=logging.DEBUG, console=_console_stream)
        else:
            apply_log_level(logging.DEBUG)
        flush_log_handlers()
        return debug_status()
    restore = _saved_python_level if _saved_python_level is not None else logging.INFO
    _saved_python_level = None
    os.environ["BLOCKCHECKS_LOG_LEVEL"] = logging.getLevelName(restore)
    if _saved_nfq:
        os.environ["BLOCKCHECKS_NFQWS2_DEBUG"] = _saved_nfq
    else:
        os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)
    _saved_nfq = None
    apply_log_level(restore)
    return debug_status()


def _redact_line(line: str) -> str:
    line = _IPV4_RE.sub("<ip>", line)
    return _HEX_RE.sub("<hex>", line)


def log_tail(
    source: str,
    *,
    tail: int = 200,
    offset: int = 0,
    strip_ansi: bool = True,
    raw: bool = False,
) -> dict:
    """Byte-offset tail. Rotation (offset > size) resets to 0 and sets truncated."""
    if source not in LOG_SOURCES:
        return {
            "ok": False,
            "error": f"invalid source: {source}",
            "source": source,
            "path": "",
            "lines": [],
            "offset": 0,
            "truncated": False,
        }
    path = _path_for_source(source)
    if path is None or not path.is_file():
        return {
            "ok": True,
            "source": source,
            "path": str(path or ""),
            "lines": [],
            "offset": 0,
            "truncated": False,
        }
    size = path.stat().st_size
    truncated = offset > size
    start = 0 if truncated else max(0, int(offset))
    with path.open("rb") as fh:
        fh.seek(start)
        data = fh.read()
    new_offset = start + len(data)
    lines = data.decode("utf-8", errors="replace").splitlines()
    if tail > 0:
        lines = lines[-int(tail) :]
    if strip_ansi:
        lines = [_ANSI_RE.sub("", ln) for ln in lines]
    if source == "nfqws2" and not raw:
        lines = [_redact_line(ln) for ln in lines]
    return {
        "ok": True,
        "source": source,
        "path": str(path),
        "lines": lines,
        "offset": new_offset,
        "truncated": truncated,
    }
