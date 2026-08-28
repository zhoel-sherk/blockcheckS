"""Tests for voice DNS discovery."""

import asyncio
import logging
from unittest.mock import MagicMock, patch

import pytest

from blockchecks.checkers.voice_dns import (
    _is_discord_voice_ip,
    check_discover_mutex,
    discover_voice_endpoints,
    pair_log_domain,
    parse_maks_ip_list,
    positive_discover_count,
    resolve_voice_targets,
    udp_discover_bootstrap,
)


@pytest.mark.asyncio
async def test_dns_discovery_discovers_endpoints():
    """DNS discovery finds at least 1 GCP endpoint."""
    eps = await discover_voice_endpoints(3, use_cache=False)
    assert len(eps) >= 1, f"Should find at least 1 endpoint, got {len(eps)}"
    for ep in eps:
        assert _is_discord_voice_ip(ep["ip"]), f"Expected Discord CDN IP, got {ep['ip']}"
        assert 50000 <= ep["port"] <= 50006, f"Port out of range: {ep['port']}"


@pytest.mark.asyncio
async def test_dns_discovery_no_duplicates():
    """DNS discovery returns unique IPs."""
    eps = await discover_voice_endpoints(10, use_cache=False)
    ips = [ep["ip"] for ep in eps]
    assert len(ips) == len(set(ips)), f"Duplicate IPs found: {ips}"


# ── pure helpers ──────────────────────────────────────────────────────


def test_positive_discover_count():
    assert positive_discover_count(5) == 5
    assert positive_discover_count(0) is None
    assert positive_discover_count(None) is None
    assert positive_discover_count(False) is None
    assert positive_discover_count("abc") is None
    assert positive_discover_count(-3) is None


def test_check_discover_mutex():
    assert check_discover_mutex(5, None) is None
    assert check_discover_mutex(None, 3) is None
    assert check_discover_mutex(5, 3) is not None


def test_resolve_voice_targets():
    assert resolve_voice_targets("1.2.3.4", 50004) == [("1.2.3.4", 50004)]
    multi = [{"ip": "1.2.3.4", "port": 50001}, {"ip": "5.6.7.8", "port": 50002}]
    assert resolve_voice_targets("x", 0, multi) == [("1.2.3.4", 50001), ("5.6.7.8", 50002)]


def test_resolve_voice_targets_dedup():
    multi = [{"ip": "1.2.3.4", "port": 50001}, {"ip": "1.2.3.4", "port": 50001}]
    assert resolve_voice_targets("x", 0, multi) == [("1.2.3.4", 50001)]


def test_resolve_voice_targets_ignores_bad():
    multi = [{"ip": "", "port": 1}, {"ip": "9.9.9.9", "port": None}, "not-a-dict"]
    assert resolve_voice_targets("x", 0, multi) == [("x", 0)]


def test_pair_log_domain():
    assert pair_log_domain("d.com", "1.2.3.4", 50001, multi=True) == "d.com@1.2.3.4:50001"
    assert pair_log_domain("d.com", "1.2.3.4", 50001, multi=False) == "d.com"


def test_parse_maks_ip_list():
    text = "1.2.3.4\n# comment\n\n5.6.7.8\n1.2.3.4\n999.1.1.1\nnot-an-ip\n"
    ips = parse_maks_ip_list(text)
    assert ips == ["1.2.3.4", "5.6.7.8"]


# ── cache ─────────────────────────────────────────────────────────────


def test_cache_roundtrip(tmp_path, monkeypatch):
    import blockchecks.checkers.voice_dns as vd

    cache = tmp_path / "cache" / "voice.json"
    monkeypatch.setattr(vd, "VOICE_DNS_CACHE_FILE", cache)
    vd._save_cache([{"ip": "1.2.3.4", "port": 50004}])
    data = vd._load_cache()
    assert data is not None
    assert data["endpoints"][0]["ip"] == "1.2.3.4"


def test_cache_expired_rotates(tmp_path, monkeypatch):
    import blockchecks.checkers.voice_dns as vd

    cache = tmp_path / "cache" / "voice.json"
    cache.parent.mkdir(parents=True)
    cache.write_text('{"timestamp": 1, "endpoints": []}')
    monkeypatch.setattr(vd, "VOICE_DNS_CACHE_FILE", cache)
    monkeypatch.setattr(vd, "CACHE_TTL_SECONDS", 60)
    assert vd._load_cache() is None
    # old cache rotated into same dir
    assert list((tmp_path / "cache").glob("voice_old_*.json"))


def test_cache_missing_returns_none(tmp_path, monkeypatch):
    import blockchecks.checkers.voice_dns as vd

    monkeypatch.setattr(vd, "VOICE_DNS_CACHE_FILE", tmp_path / "nope.json")
    assert vd._load_cache() is None


# ── fetch_maks_* ──────────────────────────────────────────────────────


def test_fetch_maks_voice_ips_ok(monkeypatch):
    import blockchecks.checkers.voice_dns as vd

    monkeypatch.setattr(vd, "_maks_get", lambda url, timeout: "1.2.3.4\n5.6.7.8\n")
    assert vd.fetch_maks_voice_ips("finland") == ["1.2.3.4", "5.6.7.8"]


def test_fetch_maks_voice_ips_fallback_global(monkeypatch):
    import blockchecks.checkers.voice_dns as vd

    monkeypatch.setattr(
        vd, "_maks_get", lambda url, timeout: None if "regions/" in url else "9.9.9.9\n"
    )
    assert vd.fetch_maks_voice_ips("russia") == ["9.9.9.9"]


def test_fetch_maks_voice_ips_fail(monkeypatch):
    import blockchecks.checkers.voice_dns as vd

    monkeypatch.setattr(vd, "_maks_get", lambda url, timeout: None)
    assert vd.fetch_maks_voice_ips("russia") == []


# ── resolve_finland_range ─────────────────────────────────────────────


def test_resolve_finland_range(monkeypatch):
    import blockchecks.checkers.voice_dns as vd

    async def fake_resolve(host, sem=None):
        if host == "finland14000.discord.gg":
            return "35.217.1.2"
        if host == "finland14001.discord.gg":
            return "8.8.8.8"  # not Discord voice CDN → filtered
        return None

    monkeypatch.setattr(vd, "_resolve_host", fake_resolve)
    monkeypatch.setattr(vd, "DNS_RANGE", (14000, 14002))
    result = asyncio.run(vd.resolve_finland_range(14000, 14002))
    assert result == {"35.217.1.2": ["finland14000.discord.gg"]}


# ── discover_dns_alive (mocked probes) ────────────────────────────────


@pytest.mark.asyncio
async def test_discover_dns_alive_returns_probed(monkeypatch):
    import blockchecks.checkers.voice_dns as vd

    monkeypatch.setattr(vd, "_load_cache", lambda: None)

    async def _fake_range():
        return {"35.1.2.3": ["finland14000.discord.gg"]}

    async def _no_maks(region, timeout=8.0):
        return []

    def fake_probe(ip, port, timeout, try_burst=False):
        return True, 12.5, "", "ip_discovery"

    monkeypatch.setattr(vd, "resolve_finland_range", _fake_range)
    monkeypatch.setattr(vd, "fetch_maks_region_ips", _no_maks)
    monkeypatch.setattr(vd, "fetch_maks_voice_ips", _no_maks)

    monkeypatch.setattr("blockchecks.checkers.udp_voice.voice_udp_probe", fake_probe)
    monkeypatch.setattr(vd, "_save_cache", lambda endpoints: None)

    with patch.object(
        vd,
        "udp_discover_bootstrap",
        return_value=MagicMock(
            __enter__=MagicMock(return_value=True), __exit__=MagicMock(return_value=None)
        ),
    ):
        eps = await vd.discover_dns_alive(
            count=1, use_cache=False, use_maks=False, use_bootstrap=False
        )
    assert eps and eps[0]["method"] == "ip_discovery"


@pytest.mark.asyncio
async def test_discover_dns_alive_no_candidates(monkeypatch):
    import blockchecks.checkers.voice_dns as vd

    monkeypatch.setattr(vd, "_load_cache", lambda: None)

    async def _empty_range():
        return {}

    async def _no_maks(region, timeout=8.0):
        return []

    monkeypatch.setattr(vd, "resolve_finland_range", _empty_range)
    monkeypatch.setattr(vd, "fetch_maks_region_ips", _no_maks)
    monkeypatch.setattr(vd, "fetch_maks_voice_ips", _no_maks)

    eps = await vd.discover_dns_alive(count=1, use_cache=False, use_maks=False, use_bootstrap=False)
    assert eps == []


def test_fetch_maks_region_ips_no_text(monkeypatch):
    import blockchecks.checkers.voice_dns as vd

    monkeypatch.setattr(vd, "_maks_get", lambda url, timeout: None)
    assert vd.fetch_maks_region_ips("russia") == []


def test_fetch_maks_region_ips_no_matching_hosts(monkeypatch):
    import blockchecks.checkers.voice_dns as vd

    monkeypatch.setattr(vd, "_maks_get", lambda url, timeout: "other.discord.gg\n")
    assert vd.fetch_maks_region_ips("russia") == []


@pytest.mark.asyncio
async def test_discover_dns_alive_stops_on_stop_event(monkeypatch):
    """A graceful stop must interrupt the candidate probe gather promptly."""
    import asyncio

    import blockchecks.checkers.voice_dns as vd

    monkeypatch.setattr(vd, "_load_cache", lambda: None)

    async def _fake_range():
        return {f"35.1.{i}.3": [f"finland{14000 + i}.discord.gg"] for i in range(8)}

    async def _no_maks(region, timeout=8.0):
        return []

    def fake_probe(ip, port, timeout, try_burst=False):
        return True, 5.0, "", "ip_discovery"

    monkeypatch.setattr(vd, "resolve_finland_range", _fake_range)
    monkeypatch.setattr(vd, "fetch_maks_region_ips", _no_maks)
    monkeypatch.setattr(vd, "fetch_maks_voice_ips", _no_maks)
    monkeypatch.setattr("blockchecks.checkers.udp_voice.voice_udp_probe", fake_probe)
    monkeypatch.setattr(vd, "_save_cache", lambda endpoints: None)

    stop = asyncio.Event()
    stop.set()

    with patch.object(
        vd,
        "udp_discover_bootstrap",
        return_value=MagicMock(
            __enter__=MagicMock(return_value=True), __exit__=MagicMock(return_value=None)
        ),
    ):
        eps = await vd.discover_dns_alive(
            count=1,
            use_cache=False,
            use_maks=False,
            use_bootstrap=False,
            stop_event=stop,
        )
    # Stop fired before probing: the gather must bail out (no hang).
    assert isinstance(eps, list)


def test_udp_discover_bootstrap_cleanup_logs_failures(caplog):
    """Bootstrap finally must log stop/cleanup failures instead of swallowing them."""
    mock_fw = MagicMock()
    mock_fw.cleanup.side_effect = OSError("iptables fail")
    mock_mgr = MagicMock()
    mock_mgr.stop.side_effect = OSError("kill fail")

    with patch("blockchecks.checkers.voice_dns.sys.platform", "linux"):
        with patch("blockchecks.service.ns_firewall.HostFirewall", return_value=mock_fw):
            with patch("blockchecks.service.nfqws2.Nfqws2Manager", return_value=mock_mgr):
                with patch.object(mock_mgr, "start_config", side_effect=RuntimeError("boot fail")):
                    with caplog.at_level(logging.WARNING, logger="blockchecks.checkers.voice_dns"):
                        with udp_discover_bootstrap(enabled=True) as active:
                            assert active is False
    mock_mgr.stop.assert_called_once()
    mock_fw.cleanup.assert_called_once()
    messages = [r.message for r in caplog.records]
    assert any("nfqws2 stop failed" in m for m in messages)
    assert any("firewall cleanup failed" in m for m in messages)
