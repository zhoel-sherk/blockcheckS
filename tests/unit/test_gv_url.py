"""Unit tests for GV-1 googlevideo videoplayback URL helpers."""

from blockchecks.checkers.youtube_url import videoplayback_host


def test_videoplayback_host():
    url = (
        "https://rr3---sn-abc.googlevideo.com/videoplayback?"
        "expire=123&sig=xyz"
    )
    assert videoplayback_host(url) == "rr3---sn-abc.googlevideo.com"
