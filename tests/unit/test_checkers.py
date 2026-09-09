"""Checker unit tests — STUN txn-id, smoke imports."""

from __future__ import annotations

import struct
from unittest.mock import MagicMock, patch

import pytest

from blockchecks.checkers.udp_voice import stun_probe
from blockchecks.engine.config import PYTHON_BIN

pytestmark = pytest.mark.unit


def test_python_bin_is_path_string():
    assert isinstance(PYTHON_BIN, str)
    assert PYTHON_BIN  # non-empty
    assert PYTHON_BIN != "PYTHON_BIN"


def test_stun_txn_id_mismatch_rejected():
    # Binding success with wrong txn id
    bad = struct.pack(">HHI", 0x0101, 0x0000, 0x2112A442) + (b"\x02" * 12)

    sock = MagicMock()
    sock.recvfrom.return_value = (bad, ("1.2.3.4", 50006))

    with (
        patch("blockchecks.checkers.udp_voice.socket.socket", return_value=sock),
        patch("blockchecks.checkers.udp_voice.random.randint", return_value=1),
    ):
        ok, _, detail = stun_probe("1.2.3.4", 50006, timeout=0.2)
    assert ok is False
    assert "invalid" in detail


def test_stun_txn_id_match_accepted():
    tid = b"\x01" * 12
    good = struct.pack(">HHI", 0x0101, 0x0000, 0x2112A442) + tid

    sock = MagicMock()
    sock.recvfrom.return_value = (good, ("1.2.3.4", 50006))

    with (
        patch("blockchecks.checkers.udp_voice.socket.socket", return_value=sock),
        patch("blockchecks.checkers.udp_voice.random.randint", return_value=1),
    ):
        ok, latency, detail = stun_probe("1.2.3.4", 50006, timeout=0.2)
    assert ok is True
    assert "STUN" in detail


@pytest.mark.unit
def test_hosts_related_subdomain_and_families():
    """§8.4: _hosts_related — subdomain ↔ apex + brand families."""
    from blockchecks.checkers.tcp_tls import _hosts_related

    assert _hosts_related("www.youtube.com", "youtube.com")
    assert _hosts_related("youtube.com", "www.youtube.com")
    assert _hosts_related("discord.gg", "discord.com")  # brand family
    assert _hosts_related("rr1---sn-x.googlevideo.com", "youtube.com")  # google family
    assert not _hosts_related("evil.example", "youtube.com")
    assert not _hosts_related("", "youtube.com")


@pytest.mark.unit
def test_is_suspicious_redirect_offsite_blockpage():
    """§8.4: blockpage redirect to a foreign host is suspicious; same-site is ok."""
    from blockchecks.checkers.tcp_tls import is_suspicious_redirect

    assert is_suspicious_redirect("youtube.com", 302, "http://blockpage.isp.ru/")
    assert not is_suspicious_redirect("youtube.com", 302, "https://www.youtube.com/")
    assert not is_suspicious_redirect("youtube.com", 200, "")


@pytest.mark.unit
def test_quic_subprocess_result_parse_failure():
    """§8.4: quic_subprocess_result maps non-JSON output to a failure dict."""
    from unittest.mock import patch

    from blockchecks.checkers.http3 import quic_subprocess_result

    class R:
        stdout = "not-json"

    with patch("subprocess.run", return_value=R()):
        d = quic_subprocess_result("ns-x", "/usr/bin/python3", "x.com", 3.0)
    assert d["success"] is False
    assert "parse" in d["error"]


@pytest.mark.unit
def test_ttl_helpers_bounds():
    """§8.4: pure ttl helpers — hops math, autottl delta, dpi reach."""
    from blockchecks.checkers.ttl_probe import autottl_delta, hops_from_ttl, ttl_reaches_dpi

    assert hops_from_ttl(64) >= 0
    assert hops_from_ttl(128) >= 0
    d = autottl_delta(10, 5)
    assert d is None or isinstance(d, int)
    # dies at DPI (dpi <= ttl < server) → True; dies before DPI or reaches
    # origin → False (semantics: "exists at DPI, dead before origin").
    assert ttl_reaches_dpi(5, dpi_hops=3, server_hops=10) is True
    assert ttl_reaches_dpi(2, dpi_hops=3, server_hops=10) is False
    assert ttl_reaches_dpi(64, dpi_hops=3, server_hops=10) is False
