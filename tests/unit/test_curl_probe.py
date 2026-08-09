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
    """googlevideo probe must set Range header and disable ECH via setopt (not options=)."""
    from blockchecks.engine.config import CURLOPT_ECH

    setopts: list[tuple] = []
    captured: dict = {}

    class FakeCurl:
        def setopt(self, opt, value):
            setopts.append((opt, value))

    class FakeSession:
        def __init__(self, **kwargs):
            captured["kwargs"] = kwargs
            self.curl = FakeCurl()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, timeout=None, **kwargs):
            captured["url"] = url
            captured["timeout"] = timeout
            captured["get_kwargs"] = kwargs
            resp = MagicMock()
            resp.status_code = 206
            resp.content = b"x" * 400
            resp.headers = {}
            return resp

    req = CurlProbeRequest(
        domain="googlevideo.com",
        curl_url="https://cdn.googlevideo.com/videoplayback?x=1",
        resolve_name="cdn.googlevideo.com",
        resolved_ip="9.9.9.9",
        googlevideo=True,
        disable_ech=True,
        timeout=5.0,
    )
    with patch("curl_cffi.Session", FakeSession):
        with patch("blockchecks.checkers.curl_probe.SOCKS5_PROXY", "socks5://127.0.0.1:11080"):
            result = run_curl_probe(req)

    assert result.http_code == 206
    assert captured["kwargs"]["headers"]["Range"] == googlevideo_range_header()
    assert captured["kwargs"]["allow_redirects"] is False
    assert captured["url"] == req.curl_url
    assert any(v == "" for o, v in setopts if "ECH" in str(o) or o == CURLOPT_ECH)
    assert any("cdn.googlevideo.com:443:9.9.9.9" in str(v) for o, v in setopts)
    # GV CDN via SOCKS proxy (socks5h = DNS through proxy) — direct egress is DPI-blocked.
    assert captured["get_kwargs"]["proxy"] == "socks5h://127.0.0.1:11080"


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


def test_curl_probe_worker_batch_mode():
    """_curl_probe_worker.run_payload mode=batch builds CurlProbeBatch and returns shape."""
    from blockchecks.engine._curl_probe_worker import run_payload

    fake_out = {
        "success": True,
        "http_code": 200,
        "latency_ms": 12.0,
        "results": [{"success": True, "http_code": 200}],
    }

    with patch(
        "blockchecks.engine._curl_probe_worker.run_curl_probe_batch",
        return_value=fake_out,
    ) as mock_batch:
        out = run_payload(
            {
                "mode": "batch",
                "curl_parallel": 2,
                "repeats": 3,
                "parallel_repeats": True,
                "repeats_mode": "full",
                "quick_break": True,
                "requests": [
                    {"domain": "discord.com", "timeout": 4.0, "resolved_ip": "1.2.3.4"},
                    {"domain": "google.com", "timeout": 5.0},
                ],
            }
        )

    assert out == fake_out
    mock_batch.assert_called_once()
    batch = mock_batch.call_args[0][0]
    assert batch.curl_parallel == 2
    assert batch.repeats == 3
    assert batch.parallel_repeats is True
    assert batch.repeats_mode == "full"
    assert batch.quick_break is True
    assert len(batch.requests) == 2
    assert batch.requests[0].domain == "discord.com"
    assert batch.requests[0].resolved_ip == "1.2.3.4"
    assert batch.requests[1].domain == "google.com"
