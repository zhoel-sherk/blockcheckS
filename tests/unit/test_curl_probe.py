"""GV-3 — curl_probe / hostfakesplit googlevideo checker tests."""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

from blockchecks.checkers.curl_probe import (
    CurlProbeRequest,
    CurlProbeResult,
    googlevideo_range_header,
    is_googlevideo_domain,
    prepare_googlevideo_probe,
    run_curl_probe,
)


def test_is_googlevideo_domain():
    assert is_googlevideo_domain("googlevideo.com")
    assert is_googlevideo_domain("RR3---sn-abc.googlevideo.com")
    assert not is_googlevideo_domain("youtube.com")


def test_googlevideo_range_header_size():
    assert googlevideo_range_header() == "bytes=0-17407"


def test_prepare_googlevideo_probe_unavailable(monkeypatch):
    monkeypatch.setattr(
        "blockchecks.checkers.youtube_url.get_fresh_url",
        lambda *a, **k: None,
    )
    _, err = prepare_googlevideo_probe("googlevideo.com")
    assert err is not None
    assert err["error"] == "gv_url_unavailable"


def test_prepare_googlevideo_probe_ok(monkeypatch):
    url = "https://rr3---sn-x.googlevideo.com/videoplayback?sig=1"
    monkeypatch.setattr(
        "blockchecks.checkers.youtube_url.get_fresh_url",
        lambda *a, **k: url,
    )
    monkeypatch.setattr(
        "blockchecks.checkers.dns_secure.doh_query",
        lambda *a, **k: (["1.2.3.4"], None, None),
    )
    monkeypatch.setattr(
        "blockchecks.checkers.dns_secure.pick_working_doh",
        lambda: "https://dns.example/dns-query",
    )
    req, err = prepare_googlevideo_probe("googlevideo.com")
    assert err is None
    assert req.curl_url == url
    assert req.googlevideo is True
    assert req.disable_ech is True
    assert req.resolve_name == "rr3---sn-x.googlevideo.com"
    assert req.resolved_ip == "1.2.3.4"


def test_run_curl_probe_googlevideo_request_shape():
    """googlevideo probe must set Range header and disable ECH (no options= kwarg)."""
    req = CurlProbeRequest(
        domain="googlevideo.com",
        curl_url="https://cdn.googlevideo.com/videoplayback?x=1",
        resolve_name="cdn.googlevideo.com",
        googlevideo=True,
        disable_ech=True,
    )
    assert req.googlevideo is True
    assert req.curl_url is not None
    assert "videoplayback" in req.curl_url
    assert googlevideo_range_header().startswith("bytes=0-")


def test_run_curl_probe_slow_rate_fails():
    class FakeCurl:
        def setopt(self, opt, value):
            pass

    class FakeSession:
        curl = FakeCurl()

        def get(self, url, timeout=None):
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b"x" * 400
            resp.headers = {}
            return resp

    with patch("curl_cffi.Session", FakeSession):
        with patch("time.perf_counter", side_effect=[0.0, 10.0]):
            result = run_curl_probe(
                CurlProbeRequest(domain="discord.com", timeout=5.0),
            )

    assert result.success is False


def test_no_options_kwarg_in_probe_sources():
    """Static guard: probe code must not use curl_cffi options=."""
    root = Path(__file__).resolve().parents[2] / "src" / "blockchecks"
    paths = [
        root / "checkers" / "curl_probe.py",
        root / "engine" / "_curl_probe_worker.py",
        root / "engine" / "async_runner.py",
        root / "engine" / "test_runner.py",
    ]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert 'kwargs["options"]' not in text
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                for kw in node.keywords:
                    assert kw.arg != "options", f"{path.name}: forbidden options= kwarg"


def test_curl_probe_result_as_dict():
    d = CurlProbeResult(success=True, http_code=200, latency_ms=1.0).as_dict()
    assert d["success"] is True
    assert d["http_code"] == 200
