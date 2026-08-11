"""Unit tests for GV-1 googlevideo videoplayback URL helpers."""

import json

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


# ── added: cache TTL / expired reuse / fresh fetch paths ──────────────


def test_cache_valid_ok():
    import time

    url = "https://x.googlevideo.com/videoplayback?ip=46.44.0.118"
    assert _cache_entry_valid({"timestamp": time.time(), "url": url})


def test_cache_expired():
    url = "https://x.googlevideo.com/videoplayback?ip=46.44.0.118"
    assert not _cache_entry_valid({"timestamp": 1, "url": url})


def test_cache_rejects_non_googlevideo():
    import time

    assert not _cache_entry_valid({"timestamp": time.time(), "url": "https://x.com"})


def test_expired_cache_url(tmp_path, monkeypatch):
    import blockchecks.checkers.youtube_url as yu

    cache = tmp_path / "gv.json"
    monkeypatch.setattr(yu, "GV_URL_CACHE_FILE", cache)
    cache.write_text('{"url": "https://a.googlevideo.com/videoplayback?ip=46.44.0.118"}')
    assert yu._expired_cache_url() is not None


def test_get_fresh_url_from_cache(tmp_path, monkeypatch):
    import blockchecks.checkers.youtube_url as yu

    cache = tmp_path / "gv.json"
    monkeypatch.setattr(yu, "GV_URL_CACHE_FILE", cache)
    import time

    url = "https://a.googlevideo.com/videoplayback?ip=46.44.0.118"
    cache.write_text(json.dumps({"timestamp": time.time(), "url": url}))
    assert yu.get_fresh_url() == url


def test_get_fresh_url_fetches(tmp_path, monkeypatch):
    import blockchecks.checkers.youtube_url as yu

    cache = tmp_path / "gv.json"
    monkeypatch.setattr(yu, "GV_URL_CACHE_FILE", cache)
    monkeypatch.setattr(yu, "_fetch_ytdlp_url", lambda *a, **k: (
        "https://a.googlevideo.com/videoplayback?ip=46.44.0.118"
    ))
    yu._fetch_fail_until = 0.0
    url = yu.get_fresh_url()
    assert "googlevideo.com" in url
    assert cache.exists()


def test_get_fresh_url_uses_cooldown(tmp_path, monkeypatch):
    import blockchecks.checkers.youtube_url as yu

    cache = tmp_path / "gv.json"
    monkeypatch.setattr(yu, "GV_URL_CACHE_FILE", cache)
    monkeypatch.setattr(yu, "_fetch_ytdlp_url", lambda *a, **k: None)
    monkeypatch.setattr(yu, "_expired_cache_url", lambda: "expired-url")
    yu._fetch_fail_until = 10 ** 12  # in future → cooldown
    assert yu.get_fresh_url() == "expired-url"


def test_get_fresh_url_no_ytdlp(tmp_path, monkeypatch):
    import shutil

    import blockchecks.checkers.youtube_url as yu
    import blockchecks.engine.config as cfg

    cache = tmp_path / "gv.json"
    monkeypatch.setattr(yu, "GV_URL_CACHE_FILE", cache)
    monkeypatch.setattr(cfg, "YTDLP_BIN", None)
    monkeypatch.setattr(cfg, "PROJECT_DIR", str(tmp_path / "nonexistent"))
    monkeypatch.setattr(yu, "_expired_cache_url", lambda: "expired-url")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    yu._fetch_fail_until = 0.0
    assert yu.get_fresh_url() == "expired-url"


def test_has_fresh_url(tmp_path, monkeypatch):
    import blockchecks.checkers.youtube_url as yu

    cache = tmp_path / "gv.json"
    monkeypatch.setattr(yu, "GV_URL_CACHE_FILE", cache)
    import time

    url = "https://a.googlevideo.com/videoplayback?ip=46.44.0.118"
    cache.write_text(json.dumps({"timestamp": time.time(), "url": url}))
    assert yu.has_fresh_url() is True


def test_fetch_ytdlp_url_parses_stdout(tmp_path, monkeypatch):
    import subprocess

    import blockchecks.checkers.youtube_url as yu

    class FakeResult:
        stdout = "https://a.googlevideo.com/videoplayback?ip=46.44.0.118\n"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeResult())
    assert yu._fetch_ytdlp_url("yt-dlp", "abc", "18") is not None


def test_fetch_ytdlp_url_timeout(tmp_path, monkeypatch):
    import subprocess

    import blockchecks.checkers.youtube_url as yu

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd=["x"], timeout=20)

    monkeypatch.setattr(subprocess, "run", boom)
    assert yu._fetch_ytdlp_url("yt-dlp", "abc", "18") is None
