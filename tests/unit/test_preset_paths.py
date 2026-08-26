"""Unit tests for preset_paths jail and sudo-aware env expansion."""

from __future__ import annotations

import pytest

from blockchecks.engine import paths
from blockchecks.engine.preset_paths import _user_ipset_dir

pytestmark = pytest.mark.unit


def test_user_ipset_dir_expands_tilde_under_sudo(monkeypatch, tmp_path):
    user_home = tmp_path / "zhoel"
    user_home.mkdir()
    ipset = user_home / ".config" / "blockcheckS" / "presets" / "ipset"
    ipset.mkdir(parents=True)

    monkeypatch.setenv("BLOCKCHECKS_IPSET_DIR", "~/.config/blockcheckS/presets/ipset")
    monkeypatch.setattr(paths, "_sudo_user_home", lambda: user_home)

    assert _user_ipset_dir().resolve() == ipset.resolve()
