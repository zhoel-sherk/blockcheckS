"""Unit tests for startup preflight (BC2-2, BC2-5, BC2-11)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.engine.preflight import (
    PreflightOptions,
    find_host_nfqws2_pids,
    run_preflight,
    run_prolog,
    run_unblocked_baseline,
)


@pytest.mark.unit
def test_find_host_nfqws2_pids_parses_pgrep():
    with patch("blockchecks.engine.preflight.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "1234\n5678\n"
        assert find_host_nfqws2_pids() == [1234, 5678]


@pytest.mark.unit
def test_unblocked_baseline_ok():
    from blockchecks.checkers.tcp_tls import TlsResult

    with patch(
        "blockchecks.engine.preflight.check_tls",
        return_value=TlsResult(domain="iana.org", success=True, http_status=200),
    ) as mock_tls:
        ok, dom = run_unblocked_baseline("iana.org")
    assert ok is True
    assert dom == "iana.org"
    mock_tls.assert_called_once()
    assert mock_tls.call_args.args[0] == "iana.org"


@pytest.mark.unit
def test_unblocked_baseline_fail():
    from blockchecks.checkers.tcp_tls import TlsResult

    with patch(
        "blockchecks.engine.preflight.check_tls",
        return_value=TlsResult(domain="iana.org", success=False, http_status=0, error="timeout"),
    ):
        ok, msg = run_unblocked_baseline("iana.org")
    assert ok is False
    assert "baseline failed" in msg
    assert "timeout" in msg


@pytest.mark.unit
def test_prolog_returns_tls_success():
    from blockchecks.checkers.tcp_tls import TlsResult

    with patch(
        "blockchecks.engine.preflight.check_tls",
        return_value=TlsResult(domain="discord.com", success=True, http_status=200),
    ):
        assert run_prolog("discord.com") is True


@pytest.mark.unit
def test_prolog_returns_tls_failure():
    from blockchecks.checkers.tcp_tls import TlsResult

    with patch(
        "blockchecks.engine.preflight.check_tls",
        return_value=TlsResult(domain="discord.com", success=False, http_status=403),
    ):
        assert run_prolog("discord.com") is False


@pytest.mark.unit
def test_preflight_aborts_on_baseline_fail():
    with patch("blockchecks.engine.preflight.run_unblocked_baseline", return_value=(False, "fail")):
        r = run_preflight(["discord.com"], PreflightOptions(skip_nfqws2_check=True))
    assert r.exit_code == 1


@pytest.mark.unit
def test_preflight_skips_domain_on_prolog():
    cache = MagicMock()
    cache.resolve.return_value = ["1.2.3.4"]
    with (
        patch("blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "")),
        patch("blockchecks.engine.preflight.run_prolog", return_value=True),
        patch("blockchecks.engine.preflight.run_port_block_probe"),
        patch("blockchecks.engine.preflight.print_port_block_report"),
        patch("blockchecks.engine.preflight.run_ip_block_cross_test"),
        patch("blockchecks.engine.preflight.print_ip_block_report"),
        patch("blockchecks.engine.preflight.check_udp_16kb", return_value=(False, "")),
        patch("blockchecks.engine.preflight._triage_domain"),
    ):
        r = run_preflight(
            ["discord.com"],
            PreflightOptions(skip_nfqws2_check=True, skip_ip_block=True, dns_cache=cache),
        )
    assert "discord.com" in r.skip_domains


@pytest.mark.unit
def test_preflight_force_keeps_domain():
    cache = MagicMock()
    cache.resolve.return_value = ["1.2.3.4"]
    with (
        patch("blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "")),
        patch("blockchecks.engine.preflight.run_prolog", return_value=True),
        patch("blockchecks.engine.preflight.run_port_block_probe"),
        patch("blockchecks.engine.preflight.print_port_block_report"),
        patch("blockchecks.engine.preflight.check_udp_16kb", return_value=(False, "")),
        patch("blockchecks.engine.preflight._triage_domain"),
    ):
        r = run_preflight(
            ["discord.com"],
            PreflightOptions(
                skip_nfqws2_check=True, skip_ip_block=True, force=True, dns_cache=cache
            ),
        )
    assert "discord.com" not in r.skip_domains


# ── added: options / dns sync / baseline fallback / audit / udp16kb ───


def test_preflight_options_from_args():
    from types import SimpleNamespace

    from blockchecks.engine.preflight import PreflightOptions

    args = SimpleNamespace(
        unblocked_dom="ref.com",
        timeout=10.0,
        skip_baseline=True,
        skip_port_block=True,
        skip_prolog=True,
        skip_ip_block=True,
        skip_nfqws2_check=True,
        abort_on_nfqws2=True,
        skip_dns_audit=True,
        force=True,
        prolog_content=True,
    )
    o = PreflightOptions.from_args(args)
    assert o.unblocked_dom == "ref.com"
    assert o.timeout == 8.0  # capped
    assert o.skip_baseline and o.force and o.verify_content


def test_sync_dns_to_data_block(tmp_path):
    import asyncio

    from blockchecks.engine.preflight import _sync_dns_to_data_block

    results = [
        {
            "domain": "a.com",
            "doh_ips": "1.2.3.4, 5.6.7.8",
            "tampered": True,
            "udp_ips": "9.9.9.9",
            "verdict": "tampered",
        }
    ]
    store = MagicMock()
    store.save_dns_records = AsyncMock()
    store.save_dns_tampered = AsyncMock()
    store.write_hosts = MagicMock()
    with (
        patch("blockchecks.data_block.provider.get_provider_dir"),
        patch("blockchecks.data_block.store.ProviderStore", return_value=store),
    ):
        asyncio.run(_sync_dns_to_data_block(results))
    store.save_dns_records.assert_awaited_once()
    store.save_dns_tampered.assert_awaited_once()
    store.write_hosts.assert_called_once()


def test_unblocked_baseline_data_block_fallback():
    from blockchecks.engine.preflight import run_unblocked_baseline

    with (
        patch("blockchecks.engine.preflight._baseline_candidates", return_value=["ref.com"]),
        patch("blockchecks.engine.preflight._data_block_cached_ip", return_value="1.2.3.4"),
        patch(
            "blockchecks.engine.preflight.check_tls",
            return_value=MagicMock(success=True, http_status=200, error=None),
        ),
    ):
        ok, dom = run_unblocked_baseline("ref.com")
    assert ok is True and dom == "ref.com"


def test_data_block_cached_ip(tmp_path):
    from blockchecks.engine.preflight import _data_block_cached_ip

    store = MagicMock()
    store.load_dns_records_sync.return_value = {"a.com": (["1.2.3.4"], "")}
    with (
        patch("blockchecks.data_block.provider.get_provider_dir"),
        patch("blockchecks.data_block.store.ProviderStore", return_value=store),
    ):
        assert _data_block_cached_ip("a.com") == "1.2.3.4"


def test_audit_domains_parallel_tampered():
    import asyncio

    from blockchecks.engine.preflight import _audit_domains_parallel

    result = MagicMock()
    result.tampering_detected = True
    result.udp_ips = ["9.9.9.9"]
    result.doh_ips = ["1.2.3.4"]
    result.verdict = "tampered"
    result.doh_server = "https://doh"
    with (
        patch("blockchecks.engine.preflight.pick_working_doh", return_value="https://doh"),
        patch("blockchecks.checkers.dns_secure.audit_domain", return_value=result),
        patch("blockchecks.engine.preflight._sync_dns_to_data_block", new=AsyncMock()),
    ):
        cache = MagicMock()
        cache.set = MagicMock()
        store = MagicMock()
        store.write_dns_audit_log = AsyncMock()
        tampered = asyncio.run(_audit_domains_parallel(["a.com"], cache, 5.0, store=store))
    assert len(tampered) == 1
    store.write_dns_audit_log.assert_awaited_once()
    cache.set.assert_called_once()


def test_check_udp_16kb_no_candidates():
    from blockchecks.engine.preflight import check_udp_16kb

    with patch("blockchecks.engine.preflight._voice_endpoint_candidates", return_value=[]):
        blocked, detail = check_udp_16kb(5.0)
    assert blocked is False
    assert "no voice endpoint" in detail


def test_check_udp_16kb_blocked():
    from blockchecks.engine.preflight import check_udp_16kb

    with (
        patch(
            "blockchecks.engine.preflight._voice_endpoint_candidates",
            return_value=[("1.2.3.4", 50004)],
        ),
        patch(
            "blockchecks.checkers.udp_voice.voice_burst_probe",
            return_value=(False, 0.0, "timeout"),
        ),
    ):
        blocked, detail = check_udp_16kb(5.0)
    assert blocked is True


def test_check_udp_16kb_ok():
    from blockchecks.engine.preflight import check_udp_16kb

    with (
        patch(
            "blockchecks.engine.preflight._voice_endpoint_candidates",
            return_value=[("1.2.3.4", 50004)],
        ),
        patch(
            "blockchecks.checkers.udp_voice.voice_burst_probe",
            return_value=(True, 5.0, ""),
        ),
    ):
        blocked, _ = check_udp_16kb(5.0)
    assert blocked is False


def test_voice_endpoint_candidates_cache(tmp_path, monkeypatch):
    import json

    from blockchecks.engine.preflight import _voice_endpoint_candidates

    cache = tmp_path / "voice.json"
    cache.write_text(json.dumps({"endpoints": [{"ip": "1.2.3.4", "port": 50001}]}))
    monkeypatch.setattr("blockchecks.engine.paths.VOICE_DNS_CACHE_FILE", cache)
    assert _voice_endpoint_candidates() == [("1.2.3.4", 50001)]


def test_voice_endpoint_candidates_default(monkeypatch, tmp_path):
    from blockchecks.engine.preflight import _voice_endpoint_candidates

    monkeypatch.setattr("blockchecks.engine.paths.VOICE_DNS_CACHE_FILE", tmp_path / "nope.json")
    assert _voice_endpoint_candidates() == [("35.217.42.214", 50004)]


def test_preflight_async_full():
    import asyncio

    from blockchecks.engine.preflight import PreflightOptions, run_preflight_async

    opts = PreflightOptions(
        skip_nfqws2_check=True,
        skip_dns_audit=True,
        timeout=5.0,
        skip_baseline=False,
        skip_ip_block=False,
        skip_port_block=True,
    )
    with (
        patch("blockchecks.engine.preflight.find_host_nfqws2_pids", return_value=[]),
        patch(
            "blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "ref.com")
        ),
        patch("blockchecks.engine.preflight.check_udp_16kb", return_value=(False, "")),
        patch("blockchecks.engine.preflight.run_prolog", return_value=False),
        patch("blockchecks.engine.preflight.run_ip_block_cross_test", return_value=MagicMock()),
        patch("blockchecks.engine.preflight.print_ip_block_report"),
        patch("blockchecks.engine.preflight._triage_domain"),
    ):
        report = asyncio.run(run_preflight_async(["discord.com"], opts))
    assert report.exit_code == 0
    assert report.baseline_ok is True
