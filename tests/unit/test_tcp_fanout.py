"""Unit tests for Phase 11 B2 multi-domain curl fan-out."""

from blockchecks.engine.tcp_fanout import (
    curl_profile,
    fanout_allowed,
    fanout_batches,
    profiles_compatible,
)


def test_curl_profile_googlevideo_special():
    p = curl_profile("googlevideo.com")
    assert p.special is True
    assert p.use_ech is False
    assert "Range" in p.headers_extra


def test_curl_profile_discord_normal():
    p = curl_profile("discord.com")
    assert p.special is False
    assert p.use_ech is True
    assert p.headers_extra == ""


def test_profiles_compatible():
    a = curl_profile("discord.com")
    b = curl_profile("youtube.com")
    c = curl_profile("googlevideo.com")
    assert profiles_compatible(a, b)
    assert not profiles_compatible(a, c)


def test_fanout_batches_splits_special():
    domains = ["discord.com", "googlevideo.com", "youtube.com", "discord.gg"]
    batches = fanout_batches(domains, curl_parallel=4)
    assert ["googlevideo.com"] in batches
    merged = [b for b in batches if len(b) > 1]
    assert any("youtube.com" in b and "discord.gg" in b for b in merged)


def test_fanout_batches_chunk_size():
    domains = [f"d{i}.example" for i in range(5)]
    batches = fanout_batches(domains, curl_parallel=2)
    assert batches == [
        ["d0.example", "d1.example"],
        ["d2.example", "d3.example"],
        ["d4.example"],
    ]


def test_fanout_allowed_family_gates():
    ok, reason = fanout_allowed(curl_parallel=4, use_family_gates=True, domains=["discord.com"])
    assert ok is False
    assert "family" in reason


def test_fanout_allowed_default_off():
    ok, _ = fanout_allowed(curl_parallel=1, use_family_gates=False, domains=["discord.com"])
    assert ok is False
