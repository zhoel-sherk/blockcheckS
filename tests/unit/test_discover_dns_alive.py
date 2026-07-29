"""Unit tests for discover_dns_alive / Maks parse / CLI mutex."""

from unittest.mock import AsyncMock, patch

import pytest

from blockchecks.checkers.voice_dns import (
    check_discover_mutex,
    discover_dns_alive,
    parse_maks_ip_list,
)


def test_check_discover_mutex_exclusive():
    assert check_discover_mutex(5, 5) is not None
    assert check_discover_mutex(1, 1) is not None
    msg = check_discover_mutex(5, 3)
    assert msg and "mutually exclusive" in msg


def test_check_discover_mutex_ok():
    assert check_discover_mutex(None, None) is None
    assert check_discover_mutex(5, None) is None
    assert check_discover_mutex(None, 5) is None
    assert check_discover_mutex(0, 5) is None
    assert check_discover_mutex(5, 0) is None


def test_parse_maks_ip_list():
    text = """
# comment
35.217.5.42
35.217.5.42
not-an-ip
35.217.1.66

1.2.3.4
"""
    ips = parse_maks_ip_list(text)
    assert ips == ["35.217.5.42", "35.217.1.66", "1.2.3.4"]


def test_parse_maks_ip_list_empty():
    assert parse_maks_ip_list("") == []
    assert parse_maks_ip_list("# only\n") == []


@pytest.mark.asyncio
async def test_discover_dns_alive_filters_dead():
    dns_map = {
        "35.217.1.1": ["finland14000.discord.gg"],
        "35.217.1.2": ["finland14001.discord.gg"],
        "35.217.1.3": ["finland14002.discord.gg"],
        "35.217.1.4": ["finland14003.discord.gg"],
        "35.217.1.5": ["finland14004.discord.gg"],
    }
    alive_ips = {"35.217.1.1", "35.217.1.3"}

    def fake_stun(ip, port, timeout=1.0):
        if ip in alive_ips:
            return True, 12.5, "ok"
        return False, 1000.0, "timeout"

    with (
        patch(
            "blockchecks.checkers.voice_dns.resolve_finland_range",
            new_callable=AsyncMock,
            return_value=dns_map,
        ),
        patch(
            "blockchecks.checkers.voice_dns.fetch_maks_voice_ips",
            return_value=[],
        ),
        patch(
            "blockchecks.checkers.voice_dns._load_cache",
            return_value=None,
        ),
        patch("blockchecks.checkers.voice_dns._save_cache"),
        patch(
            "blockchecks.checkers.udp_voice.stun_probe",
            side_effect=fake_stun,
        ),
    ):
        eps = await discover_dns_alive(5, use_cache=False, use_maks=False)

    assert len(eps) == 2
    assert {e["ip"] for e in eps} == alive_ips
    for e in eps:
        assert e["source"] == "dns-alive"
        assert e["stun_ms"] == 12.5


@pytest.mark.asyncio
async def test_discover_dns_alive_empty_when_all_timeout():
    dns_map = {"35.217.9.9": ["finland14010.discord.gg"]}

    with (
        patch(
            "blockchecks.checkers.voice_dns.resolve_finland_range",
            new_callable=AsyncMock,
            return_value=dns_map,
        ),
        patch(
            "blockchecks.checkers.voice_dns.fetch_maks_voice_ips",
            return_value=["35.217.8.8"],
        ),
        patch(
            "blockchecks.checkers.voice_dns._load_cache",
            return_value=None,
        ),
        patch("blockchecks.checkers.voice_dns._save_cache") as save,
        patch(
            "blockchecks.checkers.udp_voice.stun_probe",
            return_value=(False, 1000.0, "timeout"),
        ),
    ):
        eps = await discover_dns_alive(3, use_cache=False, use_maks=True)

    assert eps == []
    save.assert_not_called()


@pytest.mark.asyncio
async def test_discover_dns_alive_merges_maks_and_tags():
    dns_map = {"35.217.1.1": ["finland14000.discord.gg"]}

    def fake_stun(ip, port, timeout=1.0):
        return True, 5.0, "ok"

    with (
        patch(
            "blockchecks.checkers.voice_dns.resolve_finland_range",
            new_callable=AsyncMock,
            return_value=dns_map,
        ),
        patch(
            "blockchecks.checkers.voice_dns.fetch_maks_voice_ips",
            return_value=["35.217.2.2", "35.217.1.1"],  # duplicate of DNS
        ),
        patch(
            "blockchecks.checkers.voice_dns._load_cache",
            return_value=None,
        ),
        patch("blockchecks.checkers.voice_dns._save_cache"),
        patch(
            "blockchecks.checkers.udp_voice.stun_probe",
            side_effect=fake_stun,
        ),
    ):
        eps = await discover_dns_alive(5, use_cache=False, use_maks=True)

    ips = {e["ip"] for e in eps}
    assert ips == {"35.217.1.1", "35.217.2.2"}
    by_ip = {e["ip"]: e for e in eps}
    assert by_ip["35.217.1.1"]["source"] == "dns-alive"  # DNS wins over maks dup
    assert by_ip["35.217.2.2"]["source"] == "maks-alive"
    assert by_ip["35.217.2.2"]["hostname"] == "maks:finland"


@pytest.mark.asyncio
async def test_discover_dns_alive_maks_fetch_soft_fail():
    dns_map = {"35.217.3.3": ["finland14020.discord.gg"]}

    with (
        patch(
            "blockchecks.checkers.voice_dns.resolve_finland_range",
            new_callable=AsyncMock,
            return_value=dns_map,
        ),
        patch(
            "blockchecks.checkers.voice_dns.fetch_maks_voice_ips",
            return_value=[],  # soft-fail path
        ),
        patch(
            "blockchecks.checkers.voice_dns._load_cache",
            return_value=None,
        ),
        patch("blockchecks.checkers.voice_dns._save_cache"),
        patch(
            "blockchecks.checkers.udp_voice.stun_probe",
            return_value=(True, 1.0, "ok"),
        ),
    ):
        eps = await discover_dns_alive(1, use_cache=False, use_maks=True)

    assert len(eps) == 1
    assert eps[0]["ip"] == "35.217.3.3"


def test_fetch_maks_soft_fail_on_http_error():
    from blockchecks.checkers.voice_dns import fetch_maks_voice_ips

    with patch(
        "urllib.request.urlopen",
        side_effect=OSError("network down"),
    ):
        assert fetch_maks_voice_ips() == []
