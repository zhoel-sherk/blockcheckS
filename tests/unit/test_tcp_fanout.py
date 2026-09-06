"""Tests for multi-domain curl fan-out."""

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


def test_curl_profile_http_overrides_gv():
    from blockchecks.engine.tcp_fanout import CurlProfile, curl_profile

    p = curl_profile("googlevideo.com/path", protocol="http")
    assert p == CurlProfile(use_ech=False, headers_extra="", special=False)


def test_curl_profile_case_slash_and_disable_ech():
    from blockchecks.engine.tcp_fanout import curl_profile

    upper = curl_profile("GOOGLEVIDEO.com/playback", disable_ech=True)
    assert upper.special is True
    assert upper.use_ech is False
    assert "Range" in upper.headers_extra
    norm = curl_profile("Discord.com/x", disable_ech=True)
    assert norm.use_ech is False
    assert norm.headers_extra == ""
    assert norm.special is False


def test_curl_profile_ech_matrix():
    from blockchecks.engine.config import GOOGLEVIDEO_RANGE_SIZE
    from blockchecks.engine.tcp_fanout import curl_profile

    assert curl_profile("discord.com").use_ech is True
    assert curl_profile("discord.com", disable_ech=True).use_ech is False
    assert curl_profile("discord.com", protocol="http").use_ech is False
    gv = curl_profile("googlevideo.com")
    assert gv.headers_extra == f', "Range": "bytes=0-{GOOGLEVIDEO_RANGE_SIZE - 1}"'


def test_curl_profile_gv_marker_substring():
    from blockchecks.engine.tcp_fanout import curl_profile

    assert curl_profile("foo-googlevideo.example").special is True
    assert curl_profile("youtube.com").special is False
    assert curl_profile("googlevideo.example/path").special is True


def test_profiles_compatible_exact_fields():
    from blockchecks.engine.tcp_fanout import CurlProfile, curl_profile, profiles_compatible

    same = curl_profile("a.example")
    ech_off = CurlProfile(use_ech=False, headers_extra="", special=False)
    assert profiles_compatible(same, curl_profile("b.example"))
    assert profiles_compatible(same, same)
    assert not profiles_compatible(same, ech_off)
    assert profiles_compatible(ech_off, curl_profile("c.example", disable_ech=True))


def test_fanout_batches_parallel_one_solos():
    from blockchecks.engine.tcp_fanout import fanout_batches

    ds = ["discord.com", "googlevideo.com", "youtube.com"]
    assert fanout_batches(ds, curl_parallel=1) == [[d] for d in ds]


def test_fanout_batches_empty():
    from blockchecks.engine.tcp_fanout import fanout_batches

    assert fanout_batches([], curl_parallel=4) == []


def test_fanout_batches_special_resets_groups():
    from blockchecks.engine.tcp_fanout import fanout_batches

    ds = ["a.example", "b.example", "googlevideo.com", "c.example", "d.example"]
    out = fanout_batches(ds, curl_parallel=3)
    assert ["googlevideo.com"] in out
    merged = [b for b in out if len(b) > 1]
    assert merged and all("googlevideo.com" not in b for b in merged)
    assert sum(len(b) for b in merged) == 4


def test_fanout_batches_chunk_remainder_one():
    from blockchecks.engine.tcp_fanout import fanout_batches

    ds = [f"x{i}.example" for i in range(7)]
    assert fanout_batches(ds, curl_parallel=3) == [
        ["x0.example", "x1.example", "x2.example"],
        ["x3.example", "x4.example", "x5.example"],
        ["x6.example"],
    ]


def test_fanout_batches_repeated_special_all_solo():
    from blockchecks.engine.tcp_fanout import fanout_batches

    ds = ["googlevideo.com", "a.example", "b.example", "googlevideo.com"]
    out = fanout_batches(ds, curl_parallel=2)
    assert [b for b in out if b == ["googlevideo.com"]] == [["googlevideo.com"], ["googlevideo.com"]]
    assert any(len(b) == 2 and "a.example" in b and "b.example" in b for b in out)


def test_fanout_allowed_parallel_bounds():
    from blockchecks.engine.tcp_fanout import fanout_allowed

    for cp in (0, 1):
        ok, reason = fanout_allowed(curl_parallel=cp, use_family_gates=False, domains=["d.example"])
        assert ok is False
        assert reason == "curl_parallel<=1"
    ok, reason = fanout_allowed(curl_parallel=2, use_family_gates=False, domains=["d.example"])
    assert ok is True
    assert reason == ""


def test_fanout_allowed_family_gates_wins_over_special():
    from blockchecks.engine.tcp_fanout import fanout_allowed

    ok, reason = fanout_allowed(
        curl_parallel=4, use_family_gates=True, domains=["googlevideo.com"]
    )
    assert ok is False
    assert "family" in reason


def test_fanout_allowed_special_reason_formatting():
    from blockchecks.engine.tcp_fanout import fanout_allowed

    ok, reason = fanout_allowed(
        curl_parallel=2, use_family_gates=False, domains=["googlevideo.com", "d.example"]
    )
    assert ok is True
    assert "googlevideo.com" in reason and "+" not in reason

    three = [f"googlevideo{i}.com" for i in range(3)]
    ok, reason = fanout_allowed(curl_parallel=2, use_family_gates=False, domains=three)
    assert ok is True and "+" not in reason

    many = [f"googlevideo{i}.com" for i in range(5)]
    ok, reason = fanout_allowed(curl_parallel=2, use_family_gates=False, domains=many)
    assert ok is True
    assert "+2" in reason
    for name in many[:3]:
        assert name in reason
