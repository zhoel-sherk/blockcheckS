"""Tests for redirect-to-blockpage detection."""

from __future__ import annotations

import pytest

from blockchecks.checkers.tcp_tls import classify_http_status, is_suspicious_redirect

pytestmark = pytest.mark.unit


def test_same_host_redirect_ok():
    assert is_suspicious_redirect("discord.com", 302, "https://discord.com/channels") is False


def test_external_redirect_blocked():
    assert is_suspicious_redirect("signal.org", 302, "http://block.example/ban") is True


def test_http_400_classified():
    assert classify_http_status("example.com", 400) == "http 400 (likely fake packets received)"
