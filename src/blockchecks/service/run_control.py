"""Campaign run.lock and bs stop."""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from blockchecks.engine.paths import RUN_LOCK_FILE, reclaim_sudo_ownership


@dataclass(frozen=True)
class ActiveRunInfo:
    pid: int
    command: str
    started_at: str
    db_path: str | None = None
    cwd: str | None = None
    argv: list[str] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActiveRunInfo:
        return cls(
            pid=int(data["pid"]),
            command=str(data.get("command") or "unknown"),
            started_at=str(data.get("started_at") or ""),
            db_path=data.get("db_path") or None,
            cwd=data.get("cwd") or None,
            argv=list(data.get("argv") or []),
        )


def _snapshot_argv() -> list[str]:
    return list(sys.argv[1:])


def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _cmdline_looks_like_campaign(pid: int) -> bool:
    """False when /proc cmdline exists but is not a bs/blockchecks process (PID reuse)."""
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return True
    if not raw:
        return True
    text = raw.replace(b"\0", b" ").decode(errors="replace")
    return any(m in text for m in ("blockchecks", "bin/bs"))


def read_active_run() -> ActiveRunInfo | None:
    if not RUN_LOCK_FILE.is_file():
        return None
    try:
        data = json.loads(RUN_LOCK_FILE.read_text(encoding="utf-8"))
        info = ActiveRunInfo.from_dict(data)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None
    if info.pid != os.getpid() and (
        not is_pid_alive(info.pid) or not _cmdline_looks_like_campaign(info.pid)
    ):
        clear_active_run()
        return None
    return info


def register_active_run(
    command: str,
    *,
    db_path: str | Path | None = None,
    argv: list[str] | None = None,
) -> None:
    """Record this process as the active long-running campaign."""
    existing = read_active_run()
    if existing and is_pid_alive(existing.pid) and existing.pid != os.getpid():
        raise SystemExit(
            f"ERROR: active run already registered (pid {existing.pid}, "
            f"{existing.command}). Stop with: bs stop"
        )

    payload = {
        "pid": os.getpid(),
        "command": command,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "db_path": str(db_path) if db_path else None,
        "cwd": str(Path.cwd()),
        "argv": argv or _snapshot_argv(),
    }
    tmp = RUN_LOCK_FILE.with_suffix(".tmp")
    RUN_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(RUN_LOCK_FILE)
    reclaim_sudo_ownership(RUN_LOCK_FILE)


def clear_active_run() -> None:
    try:
        RUN_LOCK_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def request_graceful_stop(
    *,
    force: bool = False,
    wait_sec: float = 120.0,
) -> tuple[int, str]:
    """SIGTERM active run; wait for exit. Returns (exit_code, message)."""
    info = read_active_run()
    if info is None:
        return 2, "No active blockcheckS run (missing or stale run.lock)"

    if info.pid == os.getpid():
        return 2, "Refusing to stop: this process is the active run (use Ctrl+C)"

    try:
        os.kill(info.pid, signal.SIGTERM)
    except ProcessLookupError:
        clear_active_run()
        return 2, f"Stale run lock (pid {info.pid} not running)"
    except PermissionError:
        return 2, (
            f"Permission denied signaling pid {info.pid}. "
            "If the run was started with sudo, use: sudo bs stop"
        )

    deadline = time.monotonic() + max(1.0, float(wait_sec))
    while time.monotonic() < deadline:
        if not is_pid_alive(info.pid):
            clear_active_run()
            return 0, (
                f"Stopped pid {info.pid} ({info.command}) — "
                "DB flush/export should have completed on graceful shutdown"
            )
        time.sleep(0.25)

    if force:
        try:
            os.kill(info.pid, signal.SIGKILL)
        except ProcessLookupError:
            clear_active_run()
            return 0, f"Process {info.pid} already exited"
        except PermissionError:
            return 2, f"Permission denied killing pid {info.pid} (try sudo)"

        kill_wait = time.monotonic() + 5.0
        while time.monotonic() < kill_wait:
            if not is_pid_alive(info.pid):
                clear_active_run()
                return 0, f"Force-killed pid {info.pid} ({info.command})"
            time.sleep(0.1)
        return 1, f"Force kill sent but pid {info.pid} still alive"

    return 1, (
        f"Timed out after {wait_sec:.0f}s waiting for pid {info.pid} ({info.command}). "
        "Retry with: bs stop --force"
    )


@asynccontextmanager
async def run_session(
    command: str,
    *,
    db_path: str | Path | None = None,
    argv: list[str] | None = None,
):
    """Register run.lock for full/scan/pair; always cleared on exit."""
    register_active_run(command, db_path=db_path, argv=argv)
    try:
        yield
    finally:
        from blockchecks.service.lua_session import teardown_all_bridge_shm

        teardown_all_bridge_shm()
        clear_active_run()
