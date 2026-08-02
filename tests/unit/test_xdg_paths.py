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
    monkeypatch.setattr(paths, "DEFAULT_OUT_DIR", tmp_path / "state" / "export")
    monkeypatch.setattr(paths, "DEFAULT_SHORTLIST_DIR", tmp_path / "state" / "shortlists")
    monkeypatch.setattr(paths, "RUNTIME_LOGS_DIR", tmp_path / "state" / "logs")
    monkeypatch.setattr(paths, "USER_DATA_PRESETS_DIR", tmp_path / "state" / "presets")
    monkeypatch.setattr(paths, "USER_PRESETS_DIR", tmp_path / "config" / "presets")
    monkeypatch.setattr(paths, "BLOB_CACHE_DIR", tmp_path / "cache" / "blob-cache")
    monkeypatch.setattr(paths, "PYCACHE_DIR", tmp_path / "cache" / "pycache")
    paths.ensure_dirs()
    assert (tmp_path / "state" / "export").is_dir()
    assert (tmp_path / "cache" / "pycache").is_dir()


@pytest.mark.unit
def test_subprocess_env_sets_pycache_prefix(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "PYCACHE_DIR", tmp_path / "pycache")
    env = paths.subprocess_env({"FOO": "bar"})
    assert env["FOO"] == "bar"
    assert env["PYTHONPYCACHEPREFIX"] == str(tmp_path / "pycache")


@pytest.mark.unit
def test_expand_path_tilde(tmp_path):
    p = paths.expand_path("~/test.db", default=tmp_path / "default.db")
    assert p == (Path.home() / "test.db").resolve()
