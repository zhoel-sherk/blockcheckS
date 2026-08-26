"""Tests for curl_probe and googlevideo host checks."""

from __future__ import annotations

import ast
import json
from io import StringIO
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
    monkeypatch.setenv("BLOCKCHECKS_GV_GGC", "0")
    monkeypatch.setattr(
        "blockchecks.checkers.youtube_url.get_fresh_url",
        lambda *a, **k: None,
    )
    _, err = prepare_googlevideo_probe("googlevideo.com")
    assert err is not None
    assert err["error"] == "gv_url_unavailable"


def test_prepare_googlevideo_probe_auto_ggc_without_env(monkeypatch):
    """googlevideo auto-falls back to the deterministic GGC probe (no env)."""
    monkeypatch.delenv("BLOCKCHECKS_GV_GGC", raising=False)
    req, err = prepare_googlevideo_probe("googlevideo.com")
    assert err is None
    assert req.ggc is True
    assert req.googlevideo is True
    assert "googlevideo.com" in (req.resolve_name or "")


def test_prepare_googlevideo_probe_ok(monkeypatch):
    monkeypatch.setenv("BLOCKCHECKS_GV_GGC", "0")
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


def test_prepare_ggc_probe_uses_dns_db_when_doh_empty(monkeypatch):
    from blockchecks.checkers.curl_probe import prepare_ggc_probe
    from blockchecks.engine.ggc_pool import GgcTarget

    host = "rr7---sn-a5mek7k.googlevideo.com"
    monkeypatch.setattr(
        "blockchecks.engine.ggc_pool.pick_target",
        lambda domain_hint=None: GgcTarget(host=host, mode="synthetic"),
    )
    monkeypatch.setattr(
        "blockchecks.checkers.dns_secure.doh_query",
        lambda *a, **k: ([], "nxdomain", None),
    )
    monkeypatch.setattr(
        "blockchecks.checkers.dns_secure.pick_working_doh",
        lambda: "https://dns.example/dns-query",
    )
    monkeypatch.setattr(
        "blockchecks.data_block.store.ProviderStore.load_dns_records_sync",
        lambda self: {host: (["198.51.100.9"], "doh")},
    )
    monkeypatch.delenv("BLOCKCHECKS_GGC_IPS", raising=False)
    req, err = prepare_ggc_probe("googlevideo.com")
    assert err is None
    assert req.resolved_ip == "198.51.100.9"
    assert req.resolve_name == host
    assert req.ggc is True
    assert "/videoplayback" in (req.curl_url or "")


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

        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, timeout=None, **kwargs):
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
        root / "service" / "in_ns_workers.py",
        root / "engine" / "async_runner.py",
        root / "service" / "test_runner.py",
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
        "blockchecks.checkers.curl_probe.run_curl_probe_batch",
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


class TestGgcProbe:
    """Deterministic GGC detector — Google CDN Server header + redirect check."""

    def _mk_session(self, status, headers):
        setopts = []
        captured = {}

        class FakeCurl:
            def setopt(self, opt, value):
                setopts.append((opt, value))

        class FakeSession:
            def __init__(self, **kwargs):
                self.curl = FakeCurl()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def get(self, url, timeout=None, **kwargs):
                resp = MagicMock()
                resp.status_code = status
                resp.content = b"" if status >= 400 else b"x" * 400
                resp.headers = headers
                return resp

        return FakeSession, captured, setopts

    def test_ggc_google_server_header_passes(self):
        from blockchecks.checkers.curl_probe import run_curl_probe
        from blockchecks.engine.config import GGC_HOST

        req = CurlProbeRequest(
            domain="googlevideo.com",
            curl_url=f"https://{GGC_HOST}/videoplayback",
            resolve_name=GGC_HOST,
            resolved_ip="74.125.108.234",
            googlevideo=True,
            ggc=True,
            disable_ech=True,
            timeout=5.0,
        )
        sess, _, _ = self._mk_session(403, {"Server": "gvs 1.0"})
        with patch("curl_cffi.Session", sess):
            r = run_curl_probe(req)
        assert r.success is True
        assert r.http_code == 403

    def test_ggc_bandaid_server_header_passes(self):
        """'Bandaid Misdirected Traffic Server' is a genuine Google frontend
        on some googlevideo/static endpoints — must not be a false FAIL."""
        from blockchecks.checkers.curl_probe import run_curl_probe
        from blockchecks.engine.config import GGC_HOST

        req = CurlProbeRequest(
            domain="googlevideo.com",
            curl_url=f"https://{GGC_HOST}/videoplayback",
            resolve_name=GGC_HOST,
            resolved_ip="74.125.108.234",
            googlevideo=True,
            ggc=True,
            disable_ech=True,
            timeout=5.0,
        )
        sess, _, _ = self._mk_session(404, {"Server": "Bandaid Misdirected Traffic Server"})
        with patch("curl_cffi.Session", sess):
            r = run_curl_probe(req)
        assert r.success is True
        assert r.http_code == 404

    def test_ggc_nginx_server_header_fails(self):
        from blockchecks.checkers.curl_probe import run_curl_probe
        from blockchecks.engine.config import GGC_HOST

        req = CurlProbeRequest(
            domain="googlevideo.com",
            curl_url=f"https://{GGC_HOST}/videoplayback",
            resolve_name=GGC_HOST,
            resolved_ip="74.125.108.234",
            googlevideo=True,
            ggc=True,
            disable_ech=True,
            timeout=5.0,
        )
        sess, _, _ = self._mk_session(403, {"Server": "nginx"})
        with patch("curl_cffi.Session", sess):
            r = run_curl_probe(req)
        assert r.success is False
        assert "non-google server header" in (r.error or "")

    def test_ggc_no_server_header_fails(self):
        from blockchecks.checkers.curl_probe import run_curl_probe
        from blockchecks.engine.config import GGC_HOST

        req = CurlProbeRequest(
            domain="googlevideo.com",
            curl_url=f"https://{GGC_HOST}/videoplayback",
            resolve_name=GGC_HOST,
            resolved_ip="74.125.108.234",
            googlevideo=True,
            ggc=True,
            disable_ech=True,
            timeout=5.0,
        )
        sess, _, _ = self._mk_session(403, {})
        with patch("curl_cffi.Session", sess):
            r = run_curl_probe(req)
        assert r.success is False
        assert "server header" in (r.error or "")

    def test_ggc_redirect_to_google_passes(self):
        from blockchecks.checkers.curl_probe import run_curl_probe
        from blockchecks.engine.config import GGC_HOST

        req = CurlProbeRequest(
            domain="googlevideo.com",
            curl_url=f"https://{GGC_HOST}/videoplayback",
            resolve_name=GGC_HOST,
            resolved_ip="74.125.108.234",
            googlevideo=True,
            ggc=True,
            disable_ech=True,
            timeout=5.0,
        )
        sess, _, _ = self._mk_session(
            302,
            {"Server": "gws", "Location": "https://rr3---sn-xx.googlevideo.com/videoplayback?x=1"},
        )
        with patch("curl_cffi.Session", sess):
            r = run_curl_probe(req)
        assert r.success is True
        assert r.http_code == 302

    def test_ggc_redirect_to_foreign_host_fails(self):
        from blockchecks.checkers.curl_probe import run_curl_probe
        from blockchecks.engine.config import GGC_HOST

        req = CurlProbeRequest(
            domain="googlevideo.com",
            curl_url=f"https://{GGC_HOST}/videoplayback",
            resolve_name=GGC_HOST,
            resolved_ip="74.125.108.234",
            googlevideo=True,
            ggc=True,
            disable_ech=True,
            timeout=5.0,
        )
        sess, _, _ = self._mk_session(
            302, {"Server": "gws", "Location": "http://81.88.1.1/blocked"}
        )
        with patch("curl_cffi.Session", sess):
            r = run_curl_probe(req)
        assert r.success is False
        assert "tspu redirect" in (r.error or "")


def test_ggc_redirect_is_google():
    from blockchecks.checkers.curl_probe import _ggc_redirect_is_google

    assert _ggc_redirect_is_google("https://rr3---sn-xx.googlevideo.com/v?x=1") is True
    assert _ggc_redirect_is_google("https://foo.google.com/") is True
    assert _ggc_redirect_is_google("http://81.88.1.1/blocked") is False
    assert _ggc_redirect_is_google("https://example.ru/x") is False
    assert _ggc_redirect_is_google("") is False


def test_curl_probe_worker_single_mode():
    """run_payload mode=single routes to run_curl_probe_with_repeats."""
    from blockchecks.engine._curl_probe_worker import run_payload

    payload = {
        "mode": "single",
        "request": {
            "domain": "discord.com",
            "timeout": 5.0,
            "protocol": "tls12",
        },
        "repeats": 1,
        "parallel_repeats": False,
        "repeats_mode": "fast",
        "quick_break": False,
    }
    with patch("blockchecks.checkers.curl_probe.run_curl_probe_with_repeats") as mock:
        mock.return_value = {"ok": True}
        out = run_payload(payload)
    assert out == {"ok": True}
    mock.assert_called_once()


def test_curl_probe_worker_main_stdin():
    """main() reads JSON from stdin and prints JSON result."""
    from blockchecks.engine._curl_probe_worker import main

    payload = json.dumps(
        {
            "mode": "single",
            "request": {"domain": "discord.com", "timeout": 5.0, "protocol": "tls12"},
            "repeats": 1,
        }
    )
    with (
        patch("sys.stdin", StringIO(payload)),
        patch("blockchecks.engine._curl_probe_worker.run_payload", return_value={"ok": True}),
        patch("sys.stdout", new_callable=StringIO) as out,
    ):
        rc = main([])
    assert rc == 0
    assert '"ok": true' in out.getvalue()


def test_curl_probe_worker_main_no_input():
    from blockchecks.engine._curl_probe_worker import main

    with patch("sys.stdin", StringIO("")), patch("sys.stderr", new_callable=StringIO) as err:
        rc = main([])
    assert rc == 2
    assert "usage:" in err.getvalue()


# ── YouTube-family deterministic probe (ytcdn) ─────────────────────────


def test_is_youtube_domain():
    from blockchecks.checkers.curl_probe import is_youtube_domain

    assert is_youtube_domain("youtube.com")
    assert is_youtube_domain("www.youtube.com")
    assert is_youtube_domain("youtu.be")
    assert is_youtube_domain("googlevideo.com")
    assert is_youtube_domain("i.ytimg.com")
    assert is_youtube_domain("yt3.ggpht.com")
    assert is_youtube_domain("gvt1.com")
    assert not is_youtube_domain("discord.com")


def test_is_ytcdn_domain():
    from blockchecks.checkers.curl_probe import is_ytcdn_domain

    assert is_ytcdn_domain("i.ytimg.com")
    assert is_ytcdn_domain("yt3.ggpht.com")
    assert is_ytcdn_domain("gvt1.com")
    assert not is_ytcdn_domain("youtube.com")
    assert not is_ytcdn_domain("googlevideo.com")
    assert not is_ytcdn_domain("discord.com")


def test_ytcdn_probe_variants_order():
    from blockchecks.checkers.curl_probe import ytcdn_probe_variants

    variants = ytcdn_probe_variants("i.ytimg.com", resolved_ip="1.2.3.4")
    assert variants
    # first is the stable thumbnail (deterministic 200)
    assert any("dQw4w9WgXcQ" in v.curl_url for v in variants)
    # bare host present
    assert any(v.ytcdn_bare for v in variants)


def test_ytcdn_probe_bare_no_thumb_for_gvt1():
    from blockchecks.checkers.curl_probe import ytcdn_probe_variants

    variants = ytcdn_probe_variants("gvt1.com")
    # gvt1 has no stable thumb path → bare variant
    assert any(v.ytcdn_bare for v in variants)
    assert not any("/dQw4w9WgXcQ" in v.curl_url for v in variants)


def _run_plain_probe(status, body=b"", headers=None, protocol="tls12", domain="example.com"):
    """Run run_curl_probe with a fake session returning the given response."""
    from unittest.mock import patch

    from blockchecks.checkers.curl_probe import run_curl_probe
    from blockchecks.engine.config import GGC_HOST  # noqa: F401

    class FakeCurl:
        def setopt(self, opt, value):
            pass

    class FakeSession:
        curl = FakeCurl()

        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, timeout=None, **kwargs):
            resp = MagicMock()
            resp.status_code = status
            resp.content = body
            resp.headers = headers or {}
            return resp

    with patch("curl_cffi.Session", FakeSession):
        return run_curl_probe(
            CurlProbeRequest(domain=domain, timeout=5.0, protocol=protocol)
        )


def test_false_pass_blockpage_samehost_redirect():
    """Same-host redirect to a block/error path must FAIL (not PASS)."""
    r = _run_plain_probe(302, b"", {"Location": "https://example.com/block"})
    assert r.success is False
    assert "blockpage redirect" in (r.error or "")


def test_false_pass_304_stub_fails():
    """304 Not Modified without a conditional request is a stub, not a bypass."""
    r = _run_plain_probe(304, b"")
    assert r.success is False
    assert "304" in (r.error or "")


def test_legit_302_samehost_small_body_passes():
    """A genuine same-host redirect (non-block path) still counts as reachable."""
    r = _run_plain_probe(302, b"", {"Location": "https://example.com/next"})
    assert r.success is True


def test_200_html_binary_api_fails():
    """googlevideo binary-API probe answering text/html is a stub, not a bypass."""
    from unittest.mock import patch

    from blockchecks.checkers.curl_probe import run_curl_probe

    class FakeCurl:
        def setopt(self, opt, value):
            pass

    class FakeSession:
        curl = FakeCurl()

        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, timeout=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b"<html><body>blocked</body></html>" * 5
            resp.headers = {"Content-Type": "text/html"}
            return resp

    req = CurlProbeRequest(
        domain="googlevideo.com",
        curl_url="https://rr1---sn-xx.googlevideo.com/videoplayback",
        googlevideo=True,
        disable_ech=True,
        timeout=5.0,
    )
    with patch("curl_cffi.Session", FakeSession):
        r = run_curl_probe(req)
    assert r.success is False
    assert "text/html" in (r.error or "")


# ── TLS status classification (proving TSPU bypass) ──
#
# On Fryazino the block is a silent drop of the ClientHello → http_code=0
# (timeout/RST). Any real HTTP answer means the TLS handshake succeeded and
# DPI did NOT drop it → the bypass works. So for HTTPS probes, 401/403/404
# (with a non-stub body) are PASS, while 400 (desync corrupted the payload)
# stays FAIL.


def test_tls_403_with_body_passes():
    r = _run_plain_probe(403, b"x" * 400)
    assert r.success is True
    assert r.http_code == 403


def test_tls_404_with_body_passes():
    r = _run_plain_probe(404, b"x" * 400)
    assert r.success is True
    assert r.http_code == 404


def test_tls_401_with_body_passes():
    r = _run_plain_probe(401, b"x" * 400)
    assert r.success is True
    assert r.http_code == 401


def test_tls_404_small_body_passes():
    """Real responses from updates.discord.com/gateway.discord.gg have small bodies."""
    r = _run_plain_probe(404, b"<pre>Not Found</pre>")
    assert r.success is True
    assert r.http_code == 404
    assert r.content_ok is False


def test_tls_401_small_body_passes():
    r = _run_plain_probe(401, b"unauthorized")
    assert r.success is True
    assert r.http_code == 401
    assert r.content_ok is False


def test_tls_403_small_body_passes():
    r = _run_plain_probe(403, b"Forbidden")
    assert r.success is True
    assert r.http_code == 403
    assert r.content_ok is False


def test_tls_404_empty_body_passes():
    r = _run_plain_probe(404, b"")
    assert r.success is True
    assert r.http_code == 404
    assert r.content_ok is False


def test_discord_gg_redirect_to_com_passes():
    r = _run_plain_probe(
        301, b"", {"Location": "https://discord.com"}, domain="discord.gg"
    )
    assert r.success is True
    assert r.error is None


def test_dl_discordapp_redirect_to_com_passes():
    r = _run_plain_probe(
        301, b"", {"Location": "https://discord.com"}, domain="dl.discordapp.net"
    )
    assert r.success is True
    assert r.error is None


def test_tls_400_still_fails():
    """400 = desync corrupted the payload (fake packets) → FAIL, not a bypass."""
    r = _run_plain_probe(400, b"x" * 400)
    assert r.success is False
    assert "400" in (r.error or "")


def test_tls_404_with_rkn_body_fails():
    """Even a 404 must FAIL if the body carries a DPI/roskomnadzor stub."""
    r = _run_plain_probe(404, b"<html>blocked by roskomnadzor</html>" * 5)
    assert r.success is False


def test_tls_redirect_to_block_path_fails():
    r = _run_plain_probe(302, b"", {"Location": "https://example.com/forbidden"})
    assert r.success is False


def test_plaintext_404_fails():
    """Plaintext HTTP stays conservative: any 4xx = FAIL."""
    r = _run_plain_probe(404, b"x" * 400, protocol="http")
    assert r.success is False
    assert r.http_code == 404


def test_plaintext_200_passes():
    r = _run_plain_probe(200, b"x" * 400, protocol="http")
    assert r.success is True


def test_tls_403_with_eais_stub_fails():
    """403/404 carrying a TSPU-specific marker (eais) is a stub, not a bypass."""
    r = _run_plain_probe(403, b"<html>eais blocked resource</html>" * 5)
    assert r.success is False


def test_tls_200_with_rtru_stub_fails():
    r = _run_plain_probe(200, b"<html>warning.rt.ru blocked</html>" * 5)
    assert r.success is False


def test_small_fast_body_not_throttled_or_failed():
    """Handshake-dominated elapsed must not FAIL/THROTTLE a small 200."""

    class FakeCurl:
        def setopt(self, opt, value):
            pass

    class FakeSession:
        curl = FakeCurl()

        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, timeout=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b"x" * 400
            resp.headers = {}
            return resp

    with patch("curl_cffi.Session", FakeSession):
        with patch("time.perf_counter", side_effect=[0.0, 0.5]):
            r = run_curl_probe(CurlProbeRequest(domain="discord.com", timeout=5.0))
    assert r.success is True
    assert r.throttled is False


def test_login_error_query_not_blockpage():
    r = _run_plain_probe(302, b"", {"Location": "https://example.com/login?error=invalid"})
    assert r.success is True
    assert r.error is None


def test_plaintext_http_uses_http11(monkeypatch):
    captured: dict = {}

    class FakeCurl:
        def setopt(self, opt, value):
            pass

    class FakeSession:
        curl = FakeCurl()

        def __init__(self, **kwargs):
            captured["kwargs"] = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, timeout=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b"x" * 400
            resp.headers = {}
            return resp

    with patch("curl_cffi.Session", FakeSession):
        run_curl_probe(CurlProbeRequest(domain="example.com", timeout=5.0, protocol="http"))
    assert captured["kwargs"]["http_version"] == "v1"


def test_googlevideo_follow_keeps_resolved_ip():
    from blockchecks.checkers.curl_probe import _googlevideo_follow_request

    req = CurlProbeRequest(
        domain="googlevideo.com",
        timeout=5.0,
        resolved_ip="9.9.9.9",
        resolve_name="rr1---sn-x.googlevideo.com",
        googlevideo=True,
    )
    follow = _googlevideo_follow_request(
        req, "https://rr2---sn-y.googlevideo.com/videoplayback?id=1"
    )
    assert follow is not None
    assert follow.resolved_ip == "9.9.9.9"
    assert follow.resolve_name == "rr2---sn-y.googlevideo.com"


def test_apply_ech_off_unsupported_libcurl_is_best_effort(monkeypatch):
    """libcurl без CURLOPT_ECH → warning + None (проба НЕ абортируется)."""

    from blockchecks.checkers import curl_probe as cp

    class FakeSession:
        closed = False

        def close(self):
            self.closed = True

        class curl:  # noqa: N801
            @staticmethod
            def setopt(opt, val):
                raise RuntimeError("Failed to setopt 10325, bad argument")

    sess = FakeSession()
    assert cp._apply_ech_off(sess) is None
    assert not sess.closed, "сессия не должна закрываться — проба продолжается"


def test_open_curl_session_gg_no_ech_error(monkeypatch):
    """gv-запрос с нерабочим ECH-off открывает сессию, а не возвращает error."""
    from blockchecks.checkers.curl_probe import (
        CurlProbeRequest,
        _open_curl_session,
    )

    req = CurlProbeRequest(
        domain="googlevideo.com",
        resolved_ip="198.51.100.9",
        resolve_name="rr1---sn-x.googlevideo.com",
        curl_url="https://rr1---sn-x.googlevideo.com/videoplayback?ip=198.51.100.9",
        disable_ech=True,
        googlevideo=True,
        ggc=True,
    )
    out = _open_curl_session(req)
    if hasattr(out, "error"):  # CurlProbeResult = аборт; не должно случиться
        raise AssertionError(f"probe aborted: {out.error!r}")
    out.close()
