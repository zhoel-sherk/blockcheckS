"""Unit tests for blockchecks.checkers.tcp_tls (TlsResult helpers)."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest

from blockchecks.checkers.tcp_tls import (
    _classify_tls_error,
    _validate_content,
    check_tls,
    classify_http_status,
    is_suspicious_redirect,
    resolve_domain,
)


@pytest.mark.unit
def test_is_suspicious_redirect_same_host_ok():
    assert is_suspicious_redirect("discord.com", 301, "https://discord.com/foo") is False
    assert is_suspicious_redirect("discord.com", 302, "https://www.discord.com/") is False


@pytest.mark.unit
def test_is_suspicious_redirect_external_blocked():
    assert is_suspicious_redirect("discord.com", 301, "https://gov.ru/block") is True
    assert is_suspicious_redirect("discord.com", 200, "") is False


@pytest.mark.unit
def test_classify_http_status():
    assert classify_http_status("a.com", 301, "https://evil.com/") is not None
    assert classify_http_status("a.com", 400, "") == "http 400 (likely fake packets received)"
    assert classify_http_status("a.com", 200, "") is None


@pytest.mark.unit
def test_validate_content_small_body():
    w = _validate_content(b"tiny", 0.5, 200)
    assert any("too small" in x for x in w)


@pytest.mark.unit
def test_validate_content_small_status_ok():
    w = _validate_content(b"tiny", 0, 204)
    assert w == []


@pytest.mark.unit
def test_validate_content_slow_read():
    w = _validate_content(b"x" * 500, 5.0, 200)
    assert any("slow read" in x for x in w)


@pytest.mark.unit
def test_validate_content_dpi_pattern():
    w = _validate_content(b"roskomnadzor blockpage here", 0.1, 200)
    assert any("DPI pattern" in x for x in w)


@pytest.mark.unit
def test_classify_tls_error_labels():
    assert "timeout (DPI" in _classify_tls_error("Timeout after x", elapsed=0.2, timeout=5.0)
    assert "connection reset" in _classify_tls_error("curl reset", elapsed=1.0, timeout=5.0)
    assert "TLS error" in _classify_tls_error("ssl handshake failed", elapsed=1.0, timeout=5.0)
    assert "DNS error" in _classify_tls_error("Could not resolve host", elapsed=1.0, timeout=5.0)
    assert "mystery" in _classify_tls_error("mystery", elapsed=1.0, timeout=5.0)


def _fake_response(status, content=b"", headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.content = content
    resp.headers = headers or {}
    resp.http_version = "HTTP/2"
    return resp


@pytest.mark.unit
def test_check_tls_success():
    with (
        patch("blockchecks.checkers.tcp_tls.curl_cffi.Session") as mocksess,
        patch(
            "blockchecks.checkers.tcp_tls.time.perf_counter", side_effect=[1.0, 1.1, 1.2, 1.3, 1.4]
        ),
    ):
        inst = mocksess.return_value.__enter__.return_value
        inst.get.return_value = _fake_response(200, b"x" * 500, {"Server": "gws"})
        r = check_tls("example.com", timeout=2.0, verify_content=True)
    assert r.success is True
    assert r.http_status == 200
    assert r.protocol == "HTTP/2"


@pytest.mark.unit
def test_check_tls_redirect_fail():
    with (
        patch("blockchecks.checkers.tcp_tls.curl_cffi.Session") as mocksess,
        patch(
            "blockchecks.checkers.tcp_tls.time.perf_counter", side_effect=[1.0, 1.1, 1.2, 1.3, 1.4]
        ),
    ):
        inst = mocksess.return_value.__enter__.return_value
        inst.get.return_value = _fake_response(301, b"", {"Location": "https://gov.ru/block"})
        r = check_tls("example.com", timeout=2.0, verify_content=False)
    assert r.success is False
    assert "suspicious redirect" in r.error


@pytest.mark.unit
def test_check_tls_pre_resolved_ip_uses_curl_resolve():
    with (
        patch("blockchecks.checkers.tcp_tls.curl_cffi.Session") as mocksess,
        patch("blockchecks.checkers.dns_secure.apply_curl_resolve") as m_apply,
        patch(
            "blockchecks.checkers.tcp_tls.time.perf_counter", side_effect=[1.0, 1.1, 1.2, 1.3, 1.4]
        ),
    ):
        inst = mocksess.return_value.__enter__.return_value
        inst.get.return_value = _fake_response(200, b"x" * 500)
        check_tls("example.com", timeout=2.0, pre_resolved_ip="1.2.3.4")
    m_apply.assert_called_once()


@pytest.mark.unit
def test_check_tls_request_error_classified():
    from curl_cffi.requests import RequestsError

    with (
        patch("blockchecks.checkers.tcp_tls.curl_cffi.Session") as mocksess,
        patch(
            "blockchecks.checkers.tcp_tls.time.perf_counter", side_effect=[1.0, 1.1, 1.2, 1.3, 1.4]
        ),
    ):
        inst = mocksess.return_value.__enter__.return_value
        inst.get.side_effect = RequestsError("curl timeout")
        r = check_tls("example.com", timeout=2.0)
    assert r.success is False
    assert "timeout" in r.error


@pytest.mark.unit
def test_resolve_domain_dig_fallback():
    with patch("subprocess.run", side_effect=OSError):
        with patch(
            "blockchecks.checkers.tcp_tls.socket.getaddrinfo",
            return_value=[(socket.AF_INET, 1, 6, "", ("1.2.3.4", 443))],
        ):
            assert resolve_domain("example.com") == ["1.2.3.4"]
