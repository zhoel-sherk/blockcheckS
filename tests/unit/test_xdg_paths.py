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
    assert (tmp_path / "config" / "presets" / "ipset").is_dir()
    assert (tmp_path / "data" / "data_block" / "providers").is_dir()
    assert (tmp_path / "cache" / "pycache").is_dir()
    assert not (tmp_path / "cache" / "blob-cache").exists()
    assert not (tmp_path / "state" / "export").exists()
    assert not (tmp_path / "state" / "presets").exists()
    # sensitive dirs must be 0700 (owner-only)
    import stat as _stat

    for d in (
        tmp_path / "state",
        tmp_path / "state" / "logs",
    ):
        assert (_stat.S_IMODE(d.stat().st_mode) & 0o777) == 0o700, d


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
    assert paths.resolve_user_output_dir(kind="export") == new_export
    assert paths.resolve_user_output_dir(kind="export", allow_legacy=True) == legacy
    (new_export / "new.conf").write_text("y")
    assert paths.resolve_user_output_dir(kind="export", allow_legacy=True) == new_export


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
def test_expand_path_tilde_under_sudo(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "_sudo_user_home", lambda: Path("/home/zhoel"))
    p = paths.expand_path("~/.local/state/blockcheckS/state.db", default=tmp_path / "d.db")
    assert p == Path("/home/zhoel/.local/state/blockcheckS/state.db").resolve()


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
def test_reclaim_sudo_ownership_chowns_sqlite_in_directory(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    db = state_dir / "state.db"
    db.write_text("x")
    wal = state_dir / "state.db-wal"
    wal.write_text("w")
    shm = state_dir / "state.db-shm"
    shm.write_text("s")
    called: list[tuple] = []

    def fake_chown(path, uid, gid):
        called.append((str(path), uid, gid))

    monkeypatch.setattr(paths.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")
    monkeypatch.setattr(paths.os, "chown", fake_chown)
    paths.reclaim_sudo_ownership(state_dir)
    assert (str(state_dir), 1000, 1000) in called
    assert (str(db), 1000, 1000) in called
    assert (str(wal), 1000, 1000) in called
    assert (str(shm), 1000, 1000) in called


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


@pytest.mark.unit
def test_apply_pycache_prefix_reclaims_tree_when_root(tmp_path, monkeypatch):
    pyc = tmp_path / "pycache"
    nested = pyc / "home" / "mod.cpython-312.pyc"
    nested.parent.mkdir(parents=True)
    nested.write_bytes(b"x")
    called: list[str] = []
    monkeypatch.setattr(paths, "PYCACHE_DIR", pyc)
    monkeypatch.setattr(paths, "ensure_dirs", lambda: None)
    monkeypatch.setattr(paths.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")
    monkeypatch.setattr(paths.os, "chown", lambda path, uid, gid: called.append(str(path)))
    paths.apply_pycache_prefix()
    assert str(pyc) in called
    assert str(nested) in called


@pytest.mark.unit
def test_cwd_db_migrate_enabled_default_off(monkeypatch):
    monkeypatch.delenv("BLOCKCHECKS_MIGRATE_CWD_DB", raising=False)
    from blockchecks.engine.paths import cwd_db_migrate_enabled

    assert cwd_db_migrate_enabled(None) is False
    assert cwd_db_migrate_enabled({}) is False
    assert cwd_db_migrate_enabled({"migrate": True}) is True
    monkeypatch.setenv("BLOCKCHECKS_MIGRATE_CWD_DB", "1")
    assert cwd_db_migrate_enabled({}) is True


def test_sudo_user_xdg_fallback(monkeypatch):
    """sudo-запуск (euid=0) без явных XDG → XDG SUDO_USER, не /root."""
    from blockchecks.engine import paths as pm

    monkeypatch.setenv("BLOCKCHECKS_STATE_HOME", "")
    monkeypatch.setenv("XDG_STATE_HOME", "")
    monkeypatch.setattr(pm, "_sudo_user_home", lambda: Path("/home/zhoel"))
    resolved = pm._resolve_xdg("BLOCKCHECKS_STATE_HOME", "XDG_STATE_HOME",
                               Path("/root/.local/state"))
    assert str(resolved).startswith("/home/zhoel/")
    # явная XDG-переменная сильнее SUDO_USER
    monkeypatch.setenv("XDG_STATE_HOME", "/custom/state")
    assert str(pm._resolve_xdg("BLOCKCHECKS_STATE_HOME", "XDG_STATE_HOME",
                               Path("/root/.local/state"))) == "/custom/state"


def test_sudo_user_home_none_without_sudo(monkeypatch):
    from blockchecks.engine import paths as pm

    monkeypatch.setattr(pm.os, "geteuid", lambda: 1000)
    monkeypatch.delenv("SUDO_USER", raising=False)
    assert pm._sudo_user_home() is None
