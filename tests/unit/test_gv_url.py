"""Unit tests for GV-1 googlevideo videoplayback URL helpers."""

from blockchecks.checkers.youtube_url import (
    _cache_entry_valid,
    _signed_url_ip_family,
    videoplayback_host,
)


def test_videoplayback_host():
    url = "https://rr3---sn-abc.googlevideo.com/videoplayback?expire=123&sig=xyz"
    assert videoplayback_host(url) == "rr3---sn-abc.googlevideo.com"


def test_signed_url_ip_family_v6():
    url = "https://x.googlevideo.com/videoplayback?ip=2a0c%3A16c0%3A500%3A296%3A216%3A3cff%3Afebc%3A9217"
    assert _signed_url_ip_family(url) == "v6"


def test_signed_url_ip_family_v4():
    url = "https://x.googlevideo.com/videoplayback?ip=46.44.0.118"
    assert _signed_url_ip_family(url) == "v4"


def test_cache_rejects_ipv6_bound_url():
    import time

    url = "https://rr3---sn-abc.googlevideo.com/videoplayback?ip=2a0c%3A1%3A2%3A3"
    assert not _cache_entry_valid({"timestamp": time.time(), "url": url})
