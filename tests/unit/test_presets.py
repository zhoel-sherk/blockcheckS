"""Unit tests for cli/presets — preset listing façade."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from blockchecks.cli.presets import list_presets

pytestmark = pytest.mark.unit


def test_list_presets_with_bundled(tmp_path, capsys, monkeypatch):
    import blockchecks.cli.presets as p

    dom_dir = tmp_path / "presets" / "domains"
    strat_dir = tmp_path / "presets" / "strategies"
    dom_dir.mkdir(parents=True)
    strat_dir.mkdir(parents=True)
    (dom_dir / "general.txt").write_text("a.com\n# comment\n\nb.com\n")
    (dom_dir / "zapret.txt").write_text("x.com\n")
    (strat_dir / "quick.tls").write_text("fake:blob=stun\nfake:blob=max_ru\n")

    user_dom = tmp_path / "user" / "domains"
    user_dom.mkdir(parents=True)
    (user_dom / "mydom.txt").write_text("y.com\n")

    monkeypatch.setattr(p, "PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(p, "USER_PRESETS_DIR", tmp_path / "user")

    with patch("blockchecks.cli.presets.RESERVED_DOMAIN_FILES", set()):
        list_presets()

    out = capsys.readouterr().out
    assert "general" in out
    assert "quick" in out
    assert "mydom" in out


def test_list_presets_no_files(capsys, monkeypatch):
    import blockchecks.cli.presets as p

    empty = Path("/nonexistent-presets")
    monkeypatch.setattr(p, "PROJECT_DIR", str(empty))
    monkeypatch.setattr(p, "USER_PRESETS_DIR", empty / "user")
    list_presets()
    out = capsys.readouterr().out
    assert "Domain presets" in out
