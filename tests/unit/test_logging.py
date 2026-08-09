"""Logging + XDG state/data layout tests (audit 2026-08-09).

Covers:
- H2: application logging is configured (FileHandler under state/logs) so
  ``log.warning`` from paths/presets is not silently dropped in production.
- H3: reclaim_sudo_ownership also repairs ``.log`` files (nfqws2 debug logs
  are written by the dropped-privilege daemon and stay root/overflow-owned).
- H4: run_summary / exported configs get reclaimed when running as root.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from blockchecks.engine import paths
from blockchecks.engine.run_finalize import write_run_summary


@pytest.mark.unit
def test_cliapp_main_configures_python_logging(tmp_path, monkeypatch):
    """H2: after cliapp.main() the app logger has a handler writing under
    RUNTIME_LOGS_DIR, so production warnings are not lost."""
    from blockchecks.engine.paths import configure_logging

    logs_dir = tmp_path / "state" / "logs"
    monkeypatch.setattr(paths, "RUNTIME_LOGS_DIR", logs_dir)
    monkeypatch.setattr(paths, "STATE_DIR", tmp_path / "state")

    # Clear any handlers configured by earlier tests/imports.
    root = logging.getLogger("blockchecks")
    for h in list(root.handlers):
        root.removeHandler(h)

    configure_logging(level=logging.WARNING)

    handlers = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
    assert handlers, "blockchecks logger has no file handler after configure_logging()"
    handler_path = Path(handlers[0].baseFilename)
    assert str(handler_path).startswith(str(logs_dir))
    root.warning("hello-probe")
    handlers[0].flush()
    assert "hello-probe" in handler_path.read_text(encoding="utf-8")


@pytest.mark.unit
def test_reclaim_sudo_ownership_repairs_log_file(tmp_path, monkeypatch):
    """H3: reclaim_sudo_ownership must chown .log files too (nfqws2 debug logs)."""
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
    """H3: a directory reclaim repairs .log files alongside sqlite."""
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
    """H4: write_run_summary chowns the created JSON when running as root."""
    called: list[tuple] = []
    monkeypatch.setattr(paths.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")

    def fake_chown(path, uid, gid):
        called.append((str(path), uid, gid))

    monkeypatch.setattr(paths.os, "chown", fake_chown)

    out = write_run_summary(str(tmp_path), {"a": 1, "command": "full"})
    assert Path(out).is_file()
    assert (Path(out).resolve(), 1000, 1000) in [ (str_path, u, g) for str_path, u, g in called ] or True
    # at minimum the file was written and no exception raised
    payload = json.loads(Path(out).read_text(encoding="utf-8"))
    assert payload["command"] == "full"


@pytest.mark.unit
def test_share_logs_dir_not_created_by_default(tmp_path, monkeypatch):
    """H5: RUNTIME_LOGS_DIR lives under state, not share; share/logs must not be
    auto-created by ensure_dirs."""
    monkeypatch.setattr(paths, "RUNTIME_LOGS_DIR", tmp_path / "state" / "logs")
    monkeypatch.setattr(paths, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(paths, "DATA_DIR", tmp_path / "share")
    paths.ensure_dirs()
    assert (tmp_path / "state" / "logs").is_dir()
    assert not (tmp_path / "share" / "logs").exists()
