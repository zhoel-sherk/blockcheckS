"""Tests for SNI vs IP-block cross-check."""

from unittest.mock import MagicMock, patch

import pytest

from blockchecks.checkers.ip_block import run_ip_block_cross_test
from blockchecks.checkers.tcp_tls import TlsResult


def _tls(ok: bool, code: int = 200) -> TlsResult:
    return TlsResult(domain="x", success=ok, http_status=code)


@pytest.mark.unit
def test_skips_when_baseline_fails():
    with (
        patch(
            "blockchecks.checkers.ip_block.DnsRunCache.primary_ip",
            return_value="93.184.216.34",
        ),
        patch("blockchecks.checkers.ip_block.check_tls", return_value=_tls(False, 0)),
    ):
        r = run_ip_block_cross_test("discord.com", unblocked_domain="iana.org")
    assert r.skipped
    assert "baseline failed" in r.skip_reason


@pytest.mark.unit
def test_skips_when_doh_unresolved():
    with patch("blockchecks.checkers.ip_block.DnsRunCache.primary_ip", return_value=""):
        r = run_ip_block_cross_test("discord.com", unblocked_domain="iana.org")
    assert r.skipped
    assert "does not resolve via DoH" in r.skip_reason


@pytest.mark.unit
def test_baseline_uses_doh_pinned_ip():
    cache = MagicMock()
    cache.primary_ip.return_value = "93.184.216.34"
    cache.resolve.return_value = []
    with patch("blockchecks.checkers.ip_block.check_tls", return_value=_tls(True)) as mock_tls:
        run_ip_block_cross_test("blocked.com", "ref.com", dns_cache=cache)
    assert mock_tls.call_args_list[0].kwargs.get("pre_resolved_ip") == "93.184.216.34"


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


# baseline skip / sni-block / cdn hint / preflight / report
def test_baseline_fail_skips():
    from blockchecks.checkers.ip_block import run_ip_block_cross_test

    baseline = TlsResult(domain="ref.com", success=False, error="timeout")
    cache = MagicMock()
    cache.primary_ip.return_value = "1.2.3.4"
    with patch("blockchecks.checkers.ip_block.check_tls", return_value=baseline):
        report = run_ip_block_cross_test("blocked.com", "ref.com", dns_cache=cache)
    assert report.skipped
    assert "baseline failed" in report.skip_reason


def test_sni_block_detected_when_blocked_sni_on_clean_ip():
    from blockchecks.checkers.ip_block import run_ip_block_cross_test

    clean = TlsResult(domain="x", success=True, http_status=200)
    blocked_sni_ok = TlsResult(domain="x", success=True, http_status=200)
    unblocked_sni_fail = TlsResult(domain="x", success=False, error="reset")

    cache = MagicMock()
    cache.primary_ip.return_value = "1.2.3.4"
    cache.resolve.return_value = ["5.6.7.8", "9.9.9.9"]

    with patch(
        "blockchecks.checkers.ip_block.check_tls",
        side_effect=[
            clean,  # baseline
            blocked_sni_ok,  # blocked SNI @ clean IP
            unblocked_sni_fail,  # unblocked SNI @ blocked IP
            unblocked_sni_fail,
        ],
    ):
        report = run_ip_block_cross_test("blocked.com", "ref.com", dns_cache=cache)
    assert report.sni_block_likely
    assert report.ip_block_on == ["5.6.7.8", "9.9.9.9"]


def test_cdn_hint():
    from blockchecks.checkers.ip_block import _cdn_hint

    assert _cdn_hint(["104.16.1.1", "10.0.0.1"]) != ""
    assert _cdn_hint(["10.0.0.1"]) == ""
    assert _cdn_hint(["8.6.112.0", "8.47.69.0"]) != ""
    assert "google" in _cdn_hint(["172.217.20.164"]).lower()


def test_run_ip_block_preflight_skips_ref():
    from blockchecks.checkers.ip_block import run_ip_block_preflight

    with patch(
        "blockchecks.checkers.ip_block.run_ip_block_cross_test",
        return_value=MagicMock(),
    ) as mock:
        reports = run_ip_block_preflight(["ref.com", "a.com", "b.com"], "ref.com")
    assert len(reports) == 2
    assert mock.call_count == 2


def test_print_ip_block_report_skipped(caplog):
    from blockchecks.checkers.ip_block import IpBlockReport, print_ip_block_report

    report = IpBlockReport("blocked.com", "ref.com", skipped=True, skip_reason="no baseline")
    with caplog.at_level("INFO", logger="blockchecks"):
        print_ip_block_report(report)
    assert "SKIP" in caplog.text


def test_print_ip_block_report_full(caplog):
    from blockchecks.checkers.ip_block import IpBlockReport, print_ip_block_report

    report = IpBlockReport("blocked.com", "ref.com")
    report.baseline_ok = True
    report.unblocked_ip = "1.2.3.4"
    report.blocked_ips = ["5.6.7.8"]
    report.sni_block_likely = True
    report.ip_block_on = ["5.6.7.8"]
    probe = MagicMock()
    probe.label = "test"
    probe.result.success = True
    probe.result.http_status = 200
    probe.result.error = None
    report.probes = [probe]
    with caplog.at_level("INFO", logger="blockchecks"):
        print_ip_block_report(report)
    assert "SNI-based block likely" in caplog.text


@pytest.mark.unit
def test_ref_verified_skips_baseline_roundtrip():
    """AUDIT §2: ref verified by run_unblocked_baseline → no check_tls(ref).

    The forward probe (blocked.com SNI @ ref IP) still runs — memoization
    kills only the per-domain baseline round trip. IP is the live example.com
    edge (23.192.228.84; 93.184.216.34 died with the 2024 readdress).
    """
    cache = MagicMock()
    cache.primary_ip.return_value = "23.192.228.84"
    cache.resolve.return_value = []  # no blocked IPs → no reverse probes
    with patch("blockchecks.checkers.ip_block.check_tls") as mock_tls:
        r = run_ip_block_cross_test(
            "blocked.com", "ref.com", dns_cache=cache, ref_verified=True
        )
    # exactly the forward probe ran; no baseline round trip for ref.com
    assert [c.args[0] for c in mock_tls.call_args_list] == ["blocked.com"]
    assert not r.skipped
    assert r.baseline_ok is True
    assert r.unblocked_ip == "23.192.228.84"
    assert len(r.probes) == 1 and "blocked.com SNI" in r.probes[0].label


@pytest.mark.unit
def test_candidates_rotated_on_doh_failure():
    """AUDIT §2: ref that stops resolving falls through to the next candidate."""
    cache = MagicMock()
    cache.primary_ip.side_effect = lambda dom: "" if dom == "dead.ref" else "1.2.3.4"
    cache.resolve.return_value = []
    with patch("blockchecks.checkers.ip_block.check_tls", return_value=_tls(True)) as mock_tls:
        r = run_ip_block_cross_test(
            "blocked.com",
            "dead.ref",
            dns_cache=cache,
            ref_candidates=["dead.ref", "ripe.net"],
        )
    assert r.unblocked_domain == "ripe.net"
    assert not r.skipped
    # baseline check_tls ran for the working candidate only (not ref_verified);
    # the second call is the cross-probe of blocked.com.
    baseline_calls = [c for c in mock_tls.call_args_list if c.args[0] == "ripe.net"]
    assert len(baseline_calls) == 1


@pytest.mark.unit
def test_candidates_all_fail_skips_with_last_reason():
    cache = MagicMock()
    cache.primary_ip.return_value = ""
    with patch("blockchecks.checkers.ip_block.check_tls") as mock_tls:
        r = run_ip_block_cross_test(
            "blocked.com", "a.ref", dns_cache=cache, ref_candidates=["a.ref", "b.ref"]
        )
    assert not mock_tls.call_args_list  # no baseline TLS round trips at all
    assert r.skipped
    assert "b.ref does not resolve via DoH" in r.skip_reason
