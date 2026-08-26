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


# is_pid_alive / stale lock / stop branches
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
    monkeypatch.setattr("blockchecks.service.run_control.is_pid_alive", lambda pid: False)
    assert read_active_run() is None
    assert not run_lock_file.exists()


def test_request_stop_permission_denied(run_lock_file, monkeypatch):
    import json

    run_lock_file.write_text(json.dumps({"pid": 12345, "command": "scan"}))
    monkeypatch.setattr("blockchecks.service.run_control.is_pid_alive", lambda pid: True)

    def _kill(pid, sig):
        raise PermissionError("denied")

    monkeypatch.setattr("blockchecks.service.run_control.os.kill", _kill)
    code, msg = request_graceful_stop()
    assert code == 2
    assert "Permission denied" in msg


def test_request_stop_stale_process(run_lock_file, monkeypatch):
    import json

    run_lock_file.write_text(json.dumps({"pid": 12345, "command": "scan"}))
    monkeypatch.setattr("blockchecks.service.run_control.is_pid_alive", lambda pid: True)

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
    monkeypatch.setattr("blockchecks.service.run_control.is_pid_alive", lambda pid: True)

    def _kill(pid, sig):
        if sig == signal.SIGTERM:
            raise ProcessLookupError  # already gone before kill

    monkeypatch.setattr("blockchecks.service.run_control.os.kill", _kill)
    monkeypatch.setattr("blockchecks.service.run_control.time.sleep", lambda s: None)
    code, msg = request_graceful_stop(force=True, wait_sec=1.0)
    assert code == 2
    assert "Stale run lock" in msg


def test_cleanup_env_targets_xdg_run_lock():
    from pathlib import Path

    from blockchecks.engine.config import PROJECT_DIR

    text = (Path(PROJECT_DIR) / "scripts" / "cleanup_env.sh").read_text(encoding="utf-8")
    assert '"$STATE/run.lock"' in text
    assert "sudo pkill -9 -f" in text
    assert "sudo pkill -9 nfqws2" in text


def test_week_coverage_script_is_sequential():
    from pathlib import Path

    from blockchecks.engine.config import PROJECT_DIR

    text = (Path(PROJECT_DIR) / "scripts" / "run_week_coverage.sh").read_text(encoding="utf-8")
    assert "logs/week_cov.db" in text
    assert "logs/week_cov_udp.db" in text
    assert "bs-series" in text
    assert "--preset $preset" in text
    assert "--tcp-only" in text
    assert "--data-block-sync" in text
    assert "--adaptive-epsilon" in text
    assert "--adaptive \\" not in text
    assert "bc-nfconf" in text
    assert "discord" in text and "google-youtube" in text


def test_read_active_run_foreign_cmdline_clears(run_lock_file, monkeypatch):
    import json

    run_lock_file.write_text(json.dumps({"pid": 4242, "command": "scan"}))
    monkeypatch.setattr("blockchecks.service.run_control.is_pid_alive", lambda pid: True)
    monkeypatch.setattr(
        "blockchecks.service.run_control._cmdline_looks_like_campaign", lambda pid: False
    )
    assert read_active_run() is None
    assert not run_lock_file.exists()


def test_cmdline_looks_like_campaign_missing_proc():
    from blockchecks.service.run_control import _cmdline_looks_like_campaign

    assert _cmdline_looks_like_campaign(99999999) is True


def test_register_exclusive_lock_blocks_alive_peer(run_lock_file, monkeypatch):
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


def test_register_exclusive_lock_stale_then_acquire(run_lock_file, monkeypatch):
    import json

    run_lock_file.write_text(
        json.dumps({"pid": 4242, "command": "full", "started_at": "t"}),
        encoding="utf-8",
    )
    monkeypatch.setattr("blockchecks.service.run_control.is_pid_alive", lambda pid: False)
    register_active_run("scan", db_path="logs/x.db")
    info = read_active_run()
    assert info is not None
    assert info.pid == os.getpid()
    assert info.command == "scan"


def test_register_exclusive_lock_race_file_exists(run_lock_file, monkeypatch):
    """Second O_EXCL attempt after stale clear still blocked → SystemExit."""
    calls = {"open": 0}

    def fake_open(path, flags, mode=0o644):
        calls["open"] += 1
        if calls["open"] == 1:
            raise FileExistsError
        if calls["open"] == 2:
            raise FileExistsError
        return os.open(str(run_lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)

    monkeypatch.setattr("blockchecks.service.run_control.os.open", fake_open)
    monkeypatch.setattr(
        "blockchecks.service.run_control.read_active_run",
        lambda: None,
    )
    with pytest.raises(SystemExit, match="failed to acquire run.lock"):
        register_active_run("full", db_path=None)


def test_register_same_pid_replaces_lock(run_lock_file):
    register_active_run("full", db_path="logs/a.db")
    register_active_run("full", db_path="logs/b.db")
    info = read_active_run()
    assert info is not None
    assert info.db_path == "logs/b.db"


@pytest.mark.asyncio
async def test_run_session_teardown_scoped_shm(run_lock_file, monkeypatch):
    from blockchecks.service.run_control import run_session

    removed: list[dict] = []

    def fake_teardown(*, shm_base=None, ns_names=None, pid=None):
        removed.append({"pid": pid, "ns_names": ns_names, "shm_base": shm_base})

    monkeypatch.setattr(
        "blockchecks.service.lua_session.teardown_all_bridge_shm",
        fake_teardown,
    )

    async with run_session("full", db_path="logs/x.db"):
        assert read_active_run() is not None

    assert removed == [{"pid": os.getpid(), "ns_names": None, "shm_base": None}]
    assert read_active_run() is None
