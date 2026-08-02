"""User config.toml loader tests."""

from __future__ import annotations

import argparse

import pytest

from blockchecks.cli import user_config


@pytest.mark.unit
def test_load_user_config_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(user_config, "CONFIG_FILE", tmp_path / "missing.toml")
    assert user_config.load_user_config() == {}


@pytest.mark.unit
def test_load_user_config_parses(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        """
[paths]
db = "/tmp/custom.db"

[run]
parallel = 8
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(user_config, "CONFIG_FILE", cfg)
    data = user_config.load_user_config()
    assert data["paths"]["db"] == "/tmp/custom.db"
    assert data["run"]["parallel"] == 8


@pytest.mark.unit
def test_apply_parser_defaults(tmp_path, monkeypatch):
    p = argparse.ArgumentParser()
    p.add_argument("--db", default=None)
    p.add_argument("--parallel", type=int, default=4)
    user_config.apply_parser_defaults(
        p,
        {
            "paths": {"db": str(tmp_path / "from.toml")},
            "run": {"parallel": 6},
        },
    )
    args = p.parse_args([])
    assert args.db == str(tmp_path / "from.toml")
    assert args.parallel == 6


@pytest.mark.unit
def test_finalize_store_args(tmp_path):
    args = argparse.Namespace(db=None, out_dir=None)
    cfg = {"paths": {"db": str(tmp_path / "s.db"), "out_dir": str(tmp_path / "out")}}
    user_config.finalize_store_args(args, cfg)
    assert args.db == str(tmp_path / "s.db")
    assert args.out_dir == str(tmp_path / "out")
