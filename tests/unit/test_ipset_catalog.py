"""Unit tests for presets/ipset catalogs and overlay resolution."""

from __future__ import annotations

import ipaddress

import pytest

from blockchecks.engine import ipset_catalog as cat

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clear_catalog():
    cat.clear_ipset_cache()
    yield
    cat.clear_ipset_cache()


def test_bundled_sinkhole_contains_rfc1918():
    nets = cat.sinkhole_nets()
    addr = ipaddress.ip_address("10.1.2.3")
    assert any(addr in n for n in nets)
    assert not cat.ip_in_nets("8.8.8.8", nets)


def test_cgnat_not_in_sinkhole():
    assert cat.ip_in_nets("100.64.1.8", cat.cgnat_nets())
    assert not cat.ip_in_nets("100.64.1.8", cat.sinkhole_nets())


def test_cdn_families_google_and_discord():
    assert cat.cdn_family("172.217.20.164") == "google"
    assert cat.cdn_family("173.194.1.1") == "google"
    assert cat.cdn_family("104.16.1.1") == "cloudflare"
    assert cat.cdn_family("8.6.112.1") == "discord"
    assert cat.cdn_family("35.217.5.42") == "discord"
    assert cat.cdn_family("10.0.0.1") is None


def test_user_overlay_replaces_sinkhole(tmp_path, monkeypatch):
    user = tmp_path / "presets"
    ipset = user / "ipset"
    ipset.mkdir(parents=True)
    (ipset / "sinkhole.txt").write_text("203.0.113.0/24\n")
    monkeypatch.setattr("blockchecks.engine.preset_paths.USER_PRESETS_DIR", user)
    cat.clear_ipset_cache()
    nets = cat.sinkhole_nets()
    assert cat.ip_in_nets("203.0.113.9", nets)
    assert not cat.ip_in_nets("10.1.2.3", nets)


def test_ipset_dir_env_override(tmp_path, monkeypatch):
    ipset = tmp_path / "custom-ipset"
    ipset.mkdir()
    (ipset / "sinkhole.txt").write_text("198.51.100.0/24\n")
    monkeypatch.setenv("BLOCKCHECKS_IPSET_DIR", str(ipset))
    cat.clear_ipset_cache()
    nets = cat.sinkhole_nets()
    assert cat.ip_in_nets("198.51.100.7", nets)
    assert not cat.ip_in_nets("10.1.2.3", nets)


def test_missing_sinkhole_uses_baked(monkeypatch):
    monkeypatch.setattr(cat, "_resolve", lambda _name: None)
    cat.clear_ipset_cache()
    nets = cat.sinkhole_nets()
    assert cat.ip_in_nets("192.168.0.1", nets)


def test_expect_discord_mismatch_and_youtube_hit():
    from blockchecks.checkers.dpi_diag.dns_as import as_org_mismatches

    rows = [
        {"domain": "discord.com", "doh_ips": "1.2.3.4"},
        {"domain": "youtube.com", "doh_ips": "142.250.1.1"},
    ]
    assert as_org_mismatches(rows) == ["discord.com"]


def test_fallbacks_voice_and_ggc():
    voice = cat.fallback_endpoint("voice")
    assert voice.ip == "35.217.5.42"
    assert voice.port == 50006
    pre = cat.fallback_endpoint("voice_preflight")
    assert pre.ip == "35.217.42.214"
    assert pre.port == 50004
    assert cat.fallback_endpoint("ggc").ip == "74.125.108.234"


def test_parse_expect_and_fallbacks_files(tmp_path, monkeypatch):
    user = tmp_path / "presets"
    ipset = user / "ipset"
    ipset.mkdir(parents=True)
    (ipset / "expect.txt").write_text("example.com 192.0.2.0/24\n")
    (ipset / "fallbacks.txt").write_text("voice 192.0.2.1:9\nggc 192.0.2.2\n")
    monkeypatch.setattr("blockchecks.engine.preset_paths.USER_PRESETS_DIR", user)
    cat.clear_ipset_cache()
    expect = cat.expect_families()
    assert cat.ip_in_nets("192.0.2.8", expect["example.com"])
    assert cat.fallback_endpoint("voice").port == 9
    # missing keys stay baked
    assert cat.fallback_endpoint("voice_preflight").ip == "35.217.42.214"


def test_resolve_ipset_jail():
    from blockchecks.engine.preset_paths import PresetPathError, resolve_ipset_file

    path = resolve_ipset_file("sinkhole")
    assert path.name == "sinkhole.txt"
    with pytest.raises(PresetPathError):
        resolve_ipset_file("../sinkhole")


def test_seed_user_overlay_does_not_overwrite(tmp_path, monkeypatch):
    user = tmp_path / "presets"
    ipset = user / "ipset"
    ipset.mkdir(parents=True)
    marker = ipset / "sinkhole.txt"
    marker.write_text("# custom\n1.2.3.0/24\n")
    monkeypatch.setattr(cat, "USER_PRESETS_DIR", user)
    monkeypatch.setattr("blockchecks.engine.paths.USER_PRESETS_DIR", user)
    cat.seed_user_overlay()
    assert "1.2.3.0/24" in marker.read_text()
    assert (ipset / "cdn-google.txt").is_file()
