"""Tests for curl repeats per strategy."""

from unittest.mock import MagicMock, patch

from blockchecks.checkers.curl_probe import (
    CurlProbeRequest,
    CurlProbeResult,
    clamp_repeats,
    impersonate_target,
    repeats_from_args,
    run_curl_probe_with_repeats,
)


class _FakeSession:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_clamp_repeats():
    assert clamp_repeats(0) == 1
    assert clamp_repeats(5) == 5
    assert clamp_repeats(99) == 10


def test_fast_mode_stops_on_first_pass():
    req = CurlProbeRequest(domain="discord.com", timeout=3.0)
    calls = {"n": 0}

    def fake_probe(_req, _session, **_kw):
        calls["n"] += 1
        return CurlProbeResult(success=True, http_code=200, latency_ms=100.0)

    with (
        patch("blockchecks.checkers.curl_probe._open_curl_session", return_value=_FakeSession()),
        patch("blockchecks.checkers.curl_probe._probe_with_session", side_effect=fake_probe),
    ):
        out = run_curl_probe_with_repeats(req, repeats=3, repeats_mode="fast")
    assert out["success"] is True
    assert calls["n"] == 1


def test_stable_mode_runs_all_on_pass():
    req = CurlProbeRequest(domain="discord.com", timeout=3.0)
    calls = {"n": 0}

    def fake_probe(_req, _session, **_kw):
        calls["n"] += 1
        return CurlProbeResult(success=True, http_code=200, latency_ms=100.0)

    with (
        patch("blockchecks.checkers.curl_probe._open_curl_session", return_value=_FakeSession()),
        patch("blockchecks.checkers.curl_probe._probe_with_session", side_effect=fake_probe),
    ):
        out = run_curl_probe_with_repeats(req, repeats=3, repeats_mode="stable")
    assert out["success"] is True
    assert calls["n"] == 3


def test_stable_quick_break_on_fail():
    req = CurlProbeRequest(domain="discord.com", timeout=3.0)
    calls = {"n": 0}

    def fake_probe(_req, _session, **_kw):
        calls["n"] += 1
        return CurlProbeResult(success=False, error="timeout")

    with (
        patch("blockchecks.checkers.curl_probe._open_curl_session", return_value=_FakeSession()),
        patch("blockchecks.checkers.curl_probe._probe_with_session", side_effect=fake_probe),
    ):
        out = run_curl_probe_with_repeats(req, repeats=5, repeats_mode="stable", quick_break=True)
    assert out["success"] is False
    assert calls["n"] == 1


def test_repeats_from_args_caps_and_quick_break():
    class Args:
        repeats = 20
        parallel_repeats = False
        repeats_mode = "stable"
        scan_level = "fast"

    r, p, mode, qb = repeats_from_args(Args())
    assert r == 10
    assert p is False
    assert mode == "stable"
    assert qb is True


def test_stable_reuses_one_session():
    """PERF-7: sequential repeats share one curl_cffi Session (context manager)."""
    req = CurlProbeRequest(domain="discord.com", timeout=3.0)
    created = {"n": 0}
    gets = {"n": 0}

    class FakeCurl:
        def setopt(self, *a, **k):
            pass

    class FakeSession:
        curl = FakeCurl()

        def __init__(self, **kwargs):
            created["n"] += 1
            assert kwargs["impersonate"] == impersonate_target()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, timeout=None, **kwargs):
            assert "options" not in kwargs
            gets["n"] += 1
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b"x" * 400
            resp.headers = {}
            return resp

    with patch("curl_cffi.Session", FakeSession):
        out = run_curl_probe_with_repeats(req, repeats=3, repeats_mode="stable")
    assert created["n"] == 1
    assert gets["n"] == 3
    assert out["success"] is True
