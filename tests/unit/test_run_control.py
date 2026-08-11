"""run.lock registration and bs stop."""

from __future__ import annotations

import os
import signal

import pytest

from blockchecks.service.run_control import (
    clear_active_run,
    read_active_run,
    register_active_run,
    request_graceful_stop,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def run_lock_file(monkeypatch, tmp_path):
    lock = tmp_path / "run.lock"
    monkeypatch.setattr("blockchecks.service.run_control.RUN_LOCK_FILE", lock)
    return lock


def test_register_and_clear_run_lock(run_lock_file):
    register_active_run("full", db_path="logs/test.db", argv=["full", "--max", "1"])
    info = read_active_run()
    assert info is not None
    assert info.pid == os.getpid()
    assert info.command == "full"
    assert info.db_path == "logs/test.db"
    clear_active_run()
    assert read_active_run() is None


def test_register_blocks_second_active_run(run_lock_file, monkeypatch):
    import json

    monkeypatch.setattr(
        "blockchecks.service.run_control.is_pid_alive",
        lambda pid: pid == 4242,
    )
    run_lock_file.write_text(
        json.dumps({"pid": 4242, "command": "full", "started_at": "t"}),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit, match="active run already registered"):
        register_active_run("pair", db_path=None)


def test_request_stop_no_lock(run_lock_file):
    code, msg = request_graceful_stop(wait_sec=1.0)
    assert code == 2
    assert "No active" in msg


def test_request_stop_graceful(run_lock_file, monkeypatch):
    import json

    alive = {4242: True}

    def fake_alive(pid: int) -> bool:
        return alive.get(pid, False)

    def fake_kill(pid: int, sig: int) -> None:
        if sig == signal.SIGTERM and pid in alive:
            alive[pid] = False

    monkeypatch.setattr("blockchecks.service.run_control.is_pid_alive", fake_alive)
    monkeypatch.setattr(os, "kill", fake_kill)

    run_lock_file.write_text(
        json.dumps(
            {
                "pid": 4242,
                "command": "full",
                "started_at": "2026-01-01T00:00:00+00:00",
                "db_path": "logs/x.db",
            }
        ),
        encoding="utf-8",
    )

    code, msg = request_graceful_stop(wait_sec=2.0)
    assert code == 0
    assert "Stopped" in msg
    assert read_active_run() is None


def test_normalize_cli_args_stop_alias():
    from blockchecks.cli.cliapp import normalize_cli_args

    assert normalize_cli_args(["--stop"]) == ["stop"]
    assert normalize_cli_args(["--stop", "--force"]) == ["stop", "--force"]


# ── added: is_pid_alive / stale lock / stop branches ──────────────────


def test_is_pid_alive_current():
    import os

    from blockchecks.service.run_control import is_pid_alive

    assert is_pid_alive(os.getpid()) is True
    assert is_pid_alive(0) is False
    assert is_pid_alive(-5) is False
    assert is_pid_alive(99999999) is False


def test_read_active_run_stale_clears(run_lock_file, monkeypatch):
    import json


    run_lock_file.write_text(json.dumps({"pid": 99999999, "command": "scan"}))
    monkeypatch.setattr("blockchecks.service.run_control.is_pid_alive",
                        lambda pid: False)
    assert read_active_run() is None
    assert not run_lock_file.exists()


def test_request_stop_permission_denied(run_lock_file, monkeypatch):
    import json

    run_lock_file.write_text(json.dumps({"pid": 12345, "command": "scan"}))
    monkeypatch.setattr("blockchecks.service.run_control.is_pid_alive",
                        lambda pid: True)

    def _kill(pid, sig):
        raise PermissionError("denied")

    monkeypatch.setattr("blockchecks.service.run_control.os.kill", _kill)
    code, msg = request_graceful_stop()
    assert code == 2
    assert "Permission denied" in msg


def test_request_stop_stale_process(run_lock_file, monkeypatch):
    import json

    run_lock_file.write_text(json.dumps({"pid": 12345, "command": "scan"}))
    monkeypatch.setattr("blockchecks.service.run_control.is_pid_alive",
                        lambda pid: True)

    def _kill(pid, sig):
        raise ProcessLookupError

    monkeypatch.setattr("blockchecks.service.run_control.os.kill", _kill)
    code, msg = request_graceful_stop()
    assert code == 2
    assert "Stale run lock" in msg
    assert not run_lock_file.exists()


def test_request_stop_refuses_self(run_lock_file, monkeypatch):
    import json

    run_lock_file.write_text(json.dumps({"pid": os.getpid(), "command": "scan"}))
    code, msg = request_graceful_stop()
    assert code == 2
    assert "this process is the active run" in msg


def test_request_stop_force_immediate_exit(run_lock_file, monkeypatch):
    """force: process dies on SIGKILL → clear lock, return 0."""
    import json

    run_lock_file.write_text(json.dumps({"pid": 12345, "command": "scan"}))
    monkeypatch.setattr("blockchecks.service.run_control.is_pid_alive",
                        lambda pid: True)

    def _kill(pid, sig):
        if sig == signal.SIGTERM:
            raise ProcessLookupError  # already gone before kill
        return None

    monkeypatch.setattr("blockchecks.service.run_control.os.kill", _kill)
    monkeypatch.setattr("blockchecks.service.run_control.time.sleep",
                        lambda s: None)
    code, msg = request_graceful_stop(force=True, wait_sec=1.0)
    assert code == 2
    assert "Stale run lock" in msg
