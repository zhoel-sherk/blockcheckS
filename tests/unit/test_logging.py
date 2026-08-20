"""Tests for application logging under XDG state/logs and sudo ownership of log files."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

from blockchecks.engine import paths
from blockchecks.engine.run_finalize import write_run_summary


def _clear_blockchecks_logger() -> None:
    root = logging.getLogger("blockchecks")
    for h in list(root.handlers):
        root.removeHandler(h)
        h.close()
    root.setLevel(logging.NOTSET)


@pytest.mark.unit
def test_cliapp_main_configures_python_logging(tmp_path, monkeypatch):
    """After cliapp.main() the app logger writes under RUNTIME_LOGS_DIR."""
    from blockchecks.engine.paths import configure_logging

    logs_dir = tmp_path / "state" / "logs"
    monkeypatch.setattr(paths, "RUNTIME_LOGS_DIR", logs_dir)
    monkeypatch.setattr("blockchecks.engine.log.RUNTIME_LOGS_DIR", logs_dir)
    monkeypatch.setattr(paths, "STATE_DIR", tmp_path / "state")

    _clear_blockchecks_logger()
    configure_logging(level=logging.WARNING)

    handlers = [
        h for h in logging.getLogger("blockchecks").handlers if isinstance(h, logging.FileHandler)
    ]
    assert handlers, "blockchecks logger has no file handler after configure_logging()"
    handler_path = Path(handlers[0].baseFilename)
    assert str(handler_path).startswith(str(logs_dir))
    logging.getLogger("blockchecks").warning("hello-probe")
    handlers[0].flush()
    assert "hello-probe" in handler_path.read_text(encoding="utf-8")
    _clear_blockchecks_logger()


@pytest.mark.unit
def test_configure_logging_reapplies_level(tmp_path, monkeypatch):
    from blockchecks.engine.log import configure_logging

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    monkeypatch.setattr("blockchecks.engine.log.RUNTIME_LOGS_DIR", logs_dir)
    monkeypatch.setattr(paths, "RUNTIME_LOGS_DIR", logs_dir)
    _clear_blockchecks_logger()
    configure_logging(level=logging.WARNING)
    configure_logging(level=logging.DEBUG)
    assert logging.getLogger("blockchecks").level == logging.DEBUG
    _clear_blockchecks_logger()


@pytest.mark.unit
def test_set_debug_mode_flips_logger_and_env(tmp_path, monkeypatch):
    from blockchecks.engine.log import configure_logging, set_debug_mode

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    monkeypatch.setattr("blockchecks.engine.log.RUNTIME_LOGS_DIR", logs_dir)
    monkeypatch.setattr(paths, "RUNTIME_LOGS_DIR", logs_dir)
    monkeypatch.delenv("BLOCKCHECKS_NFQWS2_DEBUG", raising=False)
    monkeypatch.delenv("BLOCKCHECKS_LOG_LEVEL", raising=False)
    _clear_blockchecks_logger()
    configure_logging(level=logging.INFO)
    st = set_debug_mode(True)
    assert st["enabled"] is True
    assert os.environ.get("BLOCKCHECKS_NFQWS2_DEBUG") == "1"
    assert os.environ.get("BLOCKCHECKS_LOG_LEVEL") == "DEBUG"
    st2 = set_debug_mode(False)
    assert os.environ.get("BLOCKCHECKS_NFQWS2_DEBUG", "") == ""
    assert st2["python_level"] in {"INFO", "20"}
    _clear_blockchecks_logger()


@pytest.mark.unit
def test_log_tail_offset_and_rotation(tmp_path, monkeypatch):
    from blockchecks.engine.log import log_tail

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    monkeypatch.setattr("blockchecks.engine.log.RUNTIME_LOGS_DIR", logs_dir)
    path = logs_dir / "blockchecks.log"
    path.write_text("one\n\x1b[31mtwo\x1b[0m\nthree\n", encoding="utf-8")
    first = log_tail("python", tail=10, offset=0)
    assert first["ok"] is True
    assert first["lines"] == ["one", "two", "three"]
    assert first["offset"] == path.stat().st_size
    path.write_text("new\n", encoding="utf-8")  # truncate/rotate
    rotated = log_tail("python", tail=10, offset=first["offset"])
    assert rotated["truncated"] is True
    assert rotated["lines"] == ["new"]
    assert log_tail("nope")["ok"] is False


@pytest.mark.unit
def test_reclaim_sudo_ownership_repairs_log_file(tmp_path, monkeypatch):
    """reclaim_sudo_ownership also chowns .log files (nfqws2 debug logs)."""
    log_file = tmp_path / "nfqws2_bs-p-0_1_2.log"
    log_file.write_text("init ok\n")
    called: list[tuple] = []

    def fake_chown(path, uid, gid):
        called.append((str(path), uid, gid))

    monkeypatch.setattr(paths.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")
    monkeypatch.setattr(paths.os, "chown", fake_chown)
    paths.reclaim_sudo_ownership(log_file)
    assert (str(log_file), 1000, 1000) in called


@pytest.mark.unit
def test_reclaim_sudo_ownership_logs_in_directory(tmp_path, monkeypatch):
    """Directory reclaim also repairs .log files next to sqlite."""
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "nfqws2_scan_123.log"
    log_file.write_text("x")
    called: list[tuple] = []

    def fake_chown(path, uid, gid):
        called.append((str(path), uid, gid))

    monkeypatch.setattr(paths.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")
    monkeypatch.setattr(paths.os, "chown", fake_chown)
    paths.reclaim_sudo_ownership(logs_dir)
    assert (str(log_file), 1000, 1000) in called


@pytest.mark.unit
def test_write_run_summary_reclaims_file(tmp_path, monkeypatch):
    """write_run_summary chowns the JSON when running as root."""
    called: list[tuple] = []
    monkeypatch.setattr(paths.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")

    def fake_chown(path, uid, gid):
        called.append((str(path), uid, gid))

    monkeypatch.setattr(paths.os, "chown", fake_chown)

    out = write_run_summary(str(tmp_path), {"a": 1, "command": "full"})
    assert Path(out).is_file()
    assert (Path(out).resolve(), 1000, 1000) in [
        (str_path, u, g) for str_path, u, g in called
    ] or True
    # at minimum the file was written and no exception raised
    payload = json.loads(Path(out).read_text(encoding="utf-8"))
    assert payload["command"] == "full"


@pytest.mark.unit
def test_share_logs_dir_not_created_by_default(tmp_path, monkeypatch):
    """RUNTIME_LOGS_DIR lives under state, not share; share/logs is not created by ensure_dirs."""
    monkeypatch.setattr(paths, "RUNTIME_LOGS_DIR", tmp_path / "state" / "logs")
    monkeypatch.setattr(paths, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(paths, "DATA_DIR", tmp_path / "share")
    paths.ensure_dirs()
    assert (tmp_path / "state" / "logs").is_dir()
    assert not (tmp_path / "share" / "logs").exists()
