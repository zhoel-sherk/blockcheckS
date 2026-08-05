"""Unit tests for IP-block cross-test (BC2-1)."""

from unittest.mock import patch

import pytest

from blockchecks.checkers.ip_block import run_ip_block_cross_test
from blockchecks.checkers.tcp_tls import TlsResult


def _tls(ok: bool, code: int = 200) -> TlsResult:
    return TlsResult(domain="x", success=ok, http_status=code)


@pytest.mark.unit
def test_skips_when_baseline_fails():
    with patch("blockchecks.checkers.ip_block.check_tls", return_value=_tls(False, 0)):
        r = run_ip_block_cross_test("discord.com", unblocked_domain="iana.org")
    assert r.skipped
    assert "baseline failed" in r.skip_reason


@pytest.mark.unit
def test_sni_block_detected():
    with patch("blockchecks.checkers.ip_block.check_tls") as mock_tls:
        mock_tls.side_effect = [
            _tls(True, 200),  # baseline iana
            _tls(True, 301),  # discord SNI on iana IP
            _tls(False, 0),  # iana SNI on discord IP
        ]
        with (
            patch(
                "blockchecks.checkers.ip_block.DnsRunCache.primary_ip",
                return_value="93.184.216.34",
            ),
            patch(
                "blockchecks.checkers.ip_block.DnsRunCache.resolve",
                return_value=["162.159.1.1"],
            ),
        ):
            r = run_ip_block_cross_test("discord.com", unblocked_domain="iana.org")
    assert not r.skipped
    assert r.sni_block_likely
    assert "162.159.1.1" in r.ip_block_on
