"""XDG path resolution tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from blockchecks.engine import paths


@pytest.mark.unit
def test_default_paths_are_absolute():
    assert paths.CONFIG_DIR.is_absolute()
    assert paths.DATA_DIR.is_absolute()
    assert paths.STATE_DIR.is_absolute()
    assert paths.DEFAULT_DB_PATH.parent == paths.STATE_DIR


@pytest.mark.unit
def test_ensure_dirs_creates_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(paths, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(paths, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(paths, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(paths, "DEFAULT_OUT_DIR", tmp_path / "data" / "export")
    monkeypatch.setattr(paths, "DEFAULT_SHORTLIST_DIR", tmp_path / "data" / "shortlists")
    monkeypatch.setattr(paths, "_LEGACY_OUT_DIR", tmp_path / "state" / "export")
    monkeypatch.setattr(paths, "_LEGACY_SHORTLIST_DIR", tmp_path / "state" / "shortlists")
    monkeypatch.setattr(paths, "RUNTIME_LOGS_DIR", tmp_path / "state" / "logs")
    monkeypatch.setattr(paths, "USER_DATA_PRESETS_DIR", tmp_path / "state" / "presets")
    monkeypatch.setattr(paths, "USER_PRESETS_DIR", tmp_path / "config" / "presets")
    monkeypatch.setattr(paths, "BLOB_CACHE_DIR", tmp_path / "cache" / "blob-cache")
    monkeypatch.setattr(paths, "PYCACHE_DIR", tmp_path / "cache" / "pycache")
    paths.ensure_dirs()
    assert (tmp_path / "data" / "export").is_dir()
    assert (tmp_path / "cache" / "pycache").is_dir()


@pytest.mark.unit
def test_subprocess_env_sets_pycache_prefix(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "PYCACHE_DIR", tmp_path / "pycache")
    env = paths.subprocess_env({"FOO": "bar"})
    assert env["FOO"] == "bar"
    assert env["PYTHONPYCACHEPREFIX"] == str(tmp_path / "pycache")


@pytest.mark.unit
def test_subprocess_env_preserves_base_pycache_prefix(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "PYCACHE_DIR", tmp_path / "pycache")
    env = paths.subprocess_env({"PYTHONPYCACHEPREFIX": "/custom/pyc"})
    assert env["PYTHONPYCACHEPREFIX"] == "/custom/pyc"


@pytest.mark.unit
def test_resolve_user_output_dir_legacy_compat(tmp_path, monkeypatch):
    data = tmp_path / "data"
    state = tmp_path / "state"
    new_export = data / "export"
    legacy = state / "export"
    new_export.mkdir(parents=True)
    legacy.mkdir(parents=True)
    (legacy / "old.conf").write_text("x")
    monkeypatch.setattr(paths, "DEFAULT_OUT_DIR", new_export)
    monkeypatch.setattr(paths, "_LEGACY_OUT_DIR", legacy)
    assert paths.resolve_user_output_dir(kind="export") == legacy
    (new_export / "new.conf").write_text("y")
    assert paths.resolve_user_output_dir(kind="export") == new_export


@pytest.mark.unit
def test_default_out_under_data():
    assert paths.DEFAULT_OUT_DIR.parent == paths.DATA_DIR
    assert paths.DEFAULT_SHORTLIST_DIR.parent == paths.DATA_DIR
    assert paths.DEFAULT_DB_PATH.parent == paths.STATE_DIR


@pytest.mark.unit
def test_expand_path_tilde(tmp_path):
    p = paths.expand_path("~/test.db", default=tmp_path / "default.db")
    assert p == (Path.home() / "test.db").resolve()


@pytest.mark.unit
def test_reclaim_sudo_ownership_chowns_when_root(tmp_path, monkeypatch):
    target = tmp_path / "state.db"
    target.write_text("x")
    wal = tmp_path / "state.db-wal"
    wal.write_text("w")
    called: list[tuple] = []

    def fake_chown(path, uid, gid):
        called.append((str(path), uid, gid))

    monkeypatch.setattr(paths.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")
    monkeypatch.setattr(paths.os, "chown", fake_chown)
    paths.reclaim_sudo_ownership(target)
    assert (str(target), 1000, 1000) in called
    assert (str(wal), 1000, 1000) in called


@pytest.mark.unit
def test_reclaim_sudo_ownership_noop_as_user(tmp_path, monkeypatch):
    target = tmp_path / "state.db"
    target.write_text("x")
    called = []
    monkeypatch.setattr(paths.os, "geteuid", lambda: 1000)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")
    monkeypatch.setattr(paths.os, "chown", lambda *a: called.append(a))
    paths.reclaim_sudo_ownership(target)
    assert called == []


@pytest.mark.unit
def test_reclaim_sudo_ownership_warns_on_oserror(tmp_path, monkeypatch, caplog):
    target = tmp_path / "state.db"
    target.write_text("x")
    monkeypatch.setattr(paths.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")

    def boom(_path, _uid, _gid):
        raise OSError("Operation not permitted")

    monkeypatch.setattr(paths.os, "chown", boom)
    with caplog.at_level("WARNING", logger="blockchecks.engine.paths"):
        paths.reclaim_sudo_ownership(target)
    assert any("chown failed" in r.message and str(target) in r.message for r in caplog.records)
