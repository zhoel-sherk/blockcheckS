"""Unit tests for hosts-analog IP pinning (IP-PIN)."""

import pytest

from blockchecks.checkers.dns_secure import DnsRunCache
from blockchecks.checkers.ip_pin import (
    dump_pins,
    load_pins,
    parse_pins,
    save_pins,
)


@pytest.mark.unit
def test_parse_pins_basic():
    text = (
        "# comment\n"
        "discord.com 162.159.135.232\n"
        "youtube.com 142.250.75.14\n"
        "\n"
        "bad.invalid not-an-ip\n"
    )
    pins = parse_pins(text)
    assert pins == {
        "discord.com": "162.159.135.232",
        "youtube.com": "142.250.75.14",
    }


@pytest.mark.unit
def test_load_pins_missing_file(tmp_path):
    assert load_pins(str(tmp_path / "nope.txt")) == {}


@pytest.mark.unit
def test_save_load_roundtrip(tmp_path):
    path = str(tmp_path / "pins.conf")
    save_pins(path, {"discord.com": "1.2.3.4", "a.com": "5.6.7.8"})
    assert load_pins(path) == {"discord.com": "1.2.3.4", "a.com": "5.6.7.8"}


@pytest.mark.unit
def test_dump_pins_sorted():
    text = dump_pins({"b.com": "2.2.2.2", "a.com": "1.1.1.1"})
    assert text.index("a.com") < text.index("b.com")
    assert text.startswith("# blockcheckS pinned IPs")


@pytest.mark.unit
def test_dns_cache_pin_priority():
    cache = DnsRunCache()
    cache.set("discord.com", ["162.159.136.232", "162.159.135.232"])
    cache.add_pin("discord.com", "162.159.135.232")
    assert cache.primary_ip("discord.com") == "162.159.135.232"
    assert cache.resolve("discord.com")[0] == "162.159.135.232"


@pytest.mark.unit
def test_dns_cache_pin_not_in_resolve():
    cache = DnsRunCache()
    cache.set("discord.com", ["162.159.136.232"])
    cache.add_pin("discord.com", "162.159.135.232")
    ips = cache.resolve("discord.com")
    assert ips[0] == "162.159.135.232"
    assert "162.159.135.232" in ips


@pytest.mark.unit
def test_dns_cache_candidates_no_pin_priority():
    cache = DnsRunCache()
    cache.set("discord.com", ["162.159.136.232", "162.159.135.232"])
    cache.add_pin("discord.com", "162.159.135.232")
    assert cache.candidates("discord.com") == [
        "162.159.136.232",
        "162.159.135.232",
    ]


@pytest.mark.unit
def test_dns_cache_set_pins_drops_empty():
    cache = DnsRunCache()
    cache.set_pins({"discord.com": "1.1.1.1", "youtube.com": ""})
    assert cache.pins() == {"discord.com": "1.1.1.1"}


@pytest.mark.unit
def test_retry_respects_short_timeout():
    """Second IP attempt uses a reduced per-IP budget (regression guard)."""
    from blockchecks.engine import async_runner

    assert 0 < async_runner.RETRY_IP_TIMEOUT <= 3.0
