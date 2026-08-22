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


def _restore_doh_catalog(orig: tuple) -> None:
    from blockchecks.engine.config import (
        DOH_BOOTSTRAP,
        DOH_SERVERS,
        UDP_DNS_SERVERS,
        UNTRUSTED_DOH_URLS,
    )

    doh, untrusted, udp, boot = orig
    DOH_SERVERS[:] = doh
    UNTRUSTED_DOH_URLS.clear()
    UNTRUSTED_DOH_URLS.update(untrusted)
    UDP_DNS_SERVERS[:] = udp
    DOH_BOOTSTRAP.clear()
    DOH_BOOTSTRAP.update(boot)


def _snapshot_doh_catalog() -> tuple:
    from blockchecks.engine.config import (
        DOH_BOOTSTRAP,
        DOH_SERVERS,
        UDP_DNS_SERVERS,
        UNTRUSTED_DOH_URLS,
    )

    return (
        list(DOH_SERVERS),
        set(UNTRUSTED_DOH_URLS),
        list(UDP_DNS_SERVERS),
        dict(DOH_BOOTSTRAP),
    )


def test_settings_example_has_at_least_five_doh_servers():
    import tomllib

    from blockchecks.engine.settings import clear_settings_cache, load_settings

    example = Path(__file__).resolve().parents[2] / "settings.example.toml"
    data = tomllib.loads(example.read_text(encoding="utf-8"))
    servers = data["secure_dns"]["servers"]
    assert len(servers) >= 5
    assert data["secure_dns"]["enabled"] is True
    assert data["secure_dns"]["doh_server"]
    yandex = next(s for s in servers if "yandex" in s["url"])
    assert yandex["trusted"] is False
    clear_settings_cache()
    s = load_settings(config_path=str(example))
    assert len(s.doh_servers) >= 5
    assert s.udp_servers


def test_settings_doh_catalog_six_servers_rotate(tmp_path: Path, monkeypatch):
    from unittest.mock import patch

    from blockchecks.checkers.dns_secure import doh_bootstrap_ip, pick_working_doh
    from blockchecks.engine.config import DOH_SERVERS, UNTRUSTED_DOH_URLS
    from blockchecks.engine.settings import apply_settings_env, clear_settings_cache, load_settings

    snap = _snapshot_doh_catalog()
    rows = "\n".join(
        "  { "
        f'name = "d{i}", url = "https://dns{i}.example/dns-query", '
        f'ip = "1.0.0.{i}", trusted = true }},'
        for i in range(1, 7)
    )
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        "[secure_dns]\nenabled = true\nservers = [\n" + rows + "\n]\n"
        'udp = [{ name = "G", ip = "8.8.8.8" }, { name = "C", ip = "1.1.1.1" },'
        ' { name = "Q", ip = "9.9.9.9" }]\n',
        encoding="utf-8",
    )
    for key in ("BLOCKCHECKS_SECURE_DNS", "BLOCKCHECKS_DOH_SERVER"):
        monkeypatch.delenv(key, raising=False)
    clear_settings_cache()
    try:
        s = apply_settings_env(load_settings(config_path=str(cfg)))
        assert len(s.doh_servers) == 6
        assert len(DOH_SERVERS) == 6
        assert not UNTRUSTED_DOH_URLS
        assert doh_bootstrap_ip("https://dns5.example/dns-query") == "1.0.0.5"

        def fake(_domain, url, timeout=5.0):
            return (["9.9.9.9"], "", 1.0) if url.endswith("dns6.example/dns-query") else ([], "e", 1)

        with (
            patch("blockchecks.checkers.dns_secure.DEFAULT_DOH_SERVER", ""),
            patch("blockchecks.checkers.dns_secure.doh_query", side_effect=fake),
        ):
            assert pick_working_doh() == "https://dns6.example/dns-query"
    finally:
        _restore_doh_catalog(snap)


def test_settings_toml_untrusted_not_in_rotation(tmp_path: Path, monkeypatch):
    from blockchecks.checkers.dns_secure import trusted_doh_servers
    from blockchecks.engine.config import DOH_SERVERS
    from blockchecks.engine.settings import apply_settings_env, clear_settings_cache, load_settings

    snap = _snapshot_doh_catalog()
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        "[secure_dns]\nservers = [\n"
        '  { name = "Good", url = "https://dns.google/dns-query", ip = "8.8.8.8", trusted = true },\n'
        '  { name = "Yandex", url = "https://dns.yandex.ru/dns-query", ip = "77.88.8.8", trusted = false },\n'
        "]\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("BLOCKCHECKS_DOH_SERVER", raising=False)
    clear_settings_cache()
    try:
        apply_settings_env(load_settings(config_path=str(cfg)))
        assert len(DOH_SERVERS) == 2
        trusted = trusted_doh_servers()
        assert len(trusted) == 1
        assert trusted[0][0] == "https://dns.google/dns-query"
    finally:
        _restore_doh_catalog(snap)


@pytest.mark.quality
def test_settings_quality_smoke():
    from blockchecks.engine.settings import BlockchecksSettings, load_settings

    s = load_settings()
    assert isinstance(s, BlockchecksSettings)
    assert s.pool >= 1
