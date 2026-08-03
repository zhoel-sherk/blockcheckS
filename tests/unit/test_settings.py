"""BlockchecksSettings unit tests (env + TOML overlay)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from tests.unit._quality_config import tool_section

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clear_settings(monkeypatch):
    from blockchecks.engine import settings as settings_mod

    settings_mod.clear_settings_cache()
    yield
    settings_mod.clear_settings_cache()


def test_settings_policy_required_fields():
    from blockchecks.engine.settings import BlockchecksSettings

    cfg = tool_section("tool", "blockchecks", "settings")
    required = cfg.get("required_fields") or []
    assert required
    fields = BlockchecksSettings.model_fields
    for name in required:
        assert name in fields, f"missing settings field {name}"


def test_settings_defaults_without_env(monkeypatch):
    from blockchecks.engine.settings import BlockchecksSettings, clear_settings_cache

    for key in list(os.environ):
        if key.startswith("BLOCKCHECKS_"):
            monkeypatch.delenv(key, raising=False)
    clear_settings_cache()
    s = BlockchecksSettings()
    assert s.pool == 4
    assert s.secure_dns is True
    assert s.nfqws2


def test_settings_env_override(monkeypatch):
    from blockchecks.engine.settings import BlockchecksSettings, clear_settings_cache

    monkeypatch.setenv("BLOCKCHECKS_POOL", "2")
    monkeypatch.setenv("BLOCKCHECKS_SECURE_DNS", "0")
    clear_settings_cache()
    s = BlockchecksSettings()
    assert s.pool == 2
    assert s.secure_dns is False


def test_settings_toml_secure_dns(tmp_path: Path, monkeypatch):
    from blockchecks.engine.settings import clear_settings_cache, load_settings

    for key in ("BLOCKCHECKS_SECURE_DNS", "BLOCKCHECKS_DOH_SERVER", "BLOCKCHECKS_POOL"):
        monkeypatch.delenv(key, raising=False)
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        '[secure_dns]\nenabled = false\ndoh_server = "https://dns.example/dns-query"\n'
        "[run]\nparallel = 1\n",
        encoding="utf-8",
    )
    clear_settings_cache()
    s = load_settings(config_path=str(cfg))
    assert s.secure_dns is False
    assert s.doh_server == "https://dns.example/dns-query"
    assert s.pool == 1


@pytest.mark.quality
def test_settings_quality_smoke():
    from blockchecks.engine.settings import BlockchecksSettings, load_settings

    s = load_settings()
    assert isinstance(s, BlockchecksSettings)
    assert s.pool >= 1
