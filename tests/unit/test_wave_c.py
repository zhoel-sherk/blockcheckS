"""Wave C unit regressions — UA, DPI helpers, fingerprint API."""

from __future__ import annotations

import inspect

import pytest

from blockchecks.checkers.tcp_tls import DPI_FAKE_PATTERNS, check_tls
from blockchecks.engine.store import matrix_fingerprint

pytestmark = pytest.mark.unit


def test_tcp_tls_no_empty_user_agent(monkeypatch):
    """Omit empty UA so curl_cffi impersonation supplies a real browser UA."""
    captured: dict = {}

    class FakeResp:
        status_code = 200
        headers = {}
        content = b"ok"
        http_version = "2"

    class FakeSession:
        def __init__(self, *a, **k):
            captured["session_kwargs"] = k

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, **k):
            return FakeResp()

    monkeypatch.setattr("curl_cffi.Session", FakeSession)
    monkeypatch.setattr(
        "blockchecks.checkers.tcp_tls._apply_read_timeout",
        lambda *a, **k: None,
    )
    result = check_tls("example.com", timeout=1.0, verify_content=False)
    assert result.success is True
    hdrs = captured["session_kwargs"].get("headers") or {}
    assert "User-Agent" not in hdrs
    assert hdrs.get("Accept")
    # Footgun: never force empty UA string
    src = inspect.getsource(check_tls)
    assert '"User-Agent": ""' not in src
    assert "'User-Agent': ''" not in src


def test_dpi_fake_patterns_fiord_only():
    decoded = [p.decode() for p in DPI_FAKE_PATTERNS]
    assert set(decoded) == {
        "roskomnadzor",
        "rkn.gov.ru",
        "blockpage",
        "utmblock",
        "eais",
        "warning.rt.ru",
    }


def test_matrix_fingerprint_stable():
    a = matrix_fingerprint(["b", "a"], ["u"], "fast", 10)
    b = matrix_fingerprint(["a", "b"], ["u"], "fast", 10)
    assert a == b
    c = matrix_fingerprint(["a", "b"], ["u"], "full", 10)
    assert a != c
