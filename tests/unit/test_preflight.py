"""Tests for startup preflight probes."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.engine.preflight import (
    PreflightOptions,
    find_host_nfqws2_pids,
    run_preflight,
    run_prolog,
    run_unblocked_baseline,
)
from blockchecks.engine.triage import TriageProfile


@pytest.fixture(autouse=True)
def _no_provider_io():
    with (
        patch("blockchecks.engine.preflight._load_prior_triage", return_value=TriageProfile()),
        patch("blockchecks.engine.preflight._persist_triage", new_callable=AsyncMock),
    ):
        yield


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
    from blockchecks.checkers.tcp_tls import TlsResult

    cache = MagicMock()
    cache.resolve.return_value = ["1.2.3.4"]
    with (
        patch("blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "")),
        patch(
            "blockchecks.engine.preflight.run_prolog_tls",
            return_value=TlsResult(domain="discord.com", success=True, http_status=200),
        ),
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
    assert r.triage is not None
    assert r.triage.handshake_phase.value == "pass"
    assert r.triage.silent_drop_after_sni is False
    assert r.triage.rst_at_sni is False


@pytest.mark.unit
def test_preflight_skips_ip_block_on_prolog_ok_domain():
    from blockchecks.checkers.tcp_tls import TlsResult

    cache = MagicMock()
    cache.resolve.return_value = ["1.2.3.4"]
    ip_cross = MagicMock()
    with (
        patch("blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "")),
        patch(
            "blockchecks.engine.preflight.run_prolog_tls",
            return_value=TlsResult(domain="discord.gg", success=True, http_status=200),
        ),
        patch("blockchecks.engine.preflight.run_port_block_probe"),
        patch("blockchecks.engine.preflight.print_port_block_report"),
        patch("blockchecks.engine.preflight.run_ip_block_cross_test", ip_cross),
        patch("blockchecks.engine.preflight.print_ip_block_report"),
        patch("blockchecks.engine.preflight.check_udp_16kb", return_value=(False, "")),
        patch("blockchecks.engine.preflight._triage_domain"),
    ):
        run_preflight(
            ["discord.gg"],
            PreflightOptions(
                skip_nfqws2_check=True,
                skip_ip_block=False,
                skip_dns_audit=True,
                dns_cache=cache,
            ),
        )
    ip_cross.assert_not_called()


@pytest.mark.unit
def test_preflight_reuses_prepared_dns_audits():
    from blockchecks.checkers.dns_secure import DnsAuditResult

    cache = MagicMock()
    cache.resolve.return_value = ["1.2.3.4"]
    audit = DnsAuditResult(
        domain="discord.com",
        doh_ips=["1.2.3.4"],
        udp_ips=["10.0.0.1"],
        tampering_detected=True,
        verdict="tampered",
        doh_server="https://doh",
    )
    audit_fn = AsyncMock()
    sync = AsyncMock()
    with (
        patch("blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "")),
        patch("blockchecks.engine.preflight._audit_domains_parallel", audit_fn),
        patch("blockchecks.engine.preflight._sync_dns_to_data_block", sync),
        patch("blockchecks.engine.preflight.check_udp_16kb", return_value=(False, "")),
        patch("blockchecks.engine.preflight.run_prolog_tls"),
        patch("blockchecks.engine.preflight._triage_domain"),
        patch("blockchecks.engine.preflight.run_port_block_probe"),
        patch("blockchecks.engine.preflight.print_port_block_report"),
    ):
        r = run_preflight(
            ["discord.com"],
            PreflightOptions(
                skip_nfqws2_check=True,
                skip_ip_block=True,
                skip_port_block=True,
                skip_prolog=True,
                dns_cache=cache,
                dns_audits=[audit],
            ),
        )
    audit_fn.assert_not_called()
    sync.assert_awaited()
    assert r.triage.dns_hijacked is True


@pytest.mark.unit
def test_no_preflight_skips_udp_l3_and_persist():
    from types import SimpleNamespace

    prior = TriageProfile(udp_blocked=True, viable_foolings=["tcp_ts=-1000"])
    persist = AsyncMock()
    udp = MagicMock(return_value=(False, "answered"))
    l3 = MagicMock()
    with (
        patch("blockchecks.engine.preflight._load_prior_triage", return_value=prior),
        patch("blockchecks.engine.preflight._persist_triage", persist),
        patch("blockchecks.engine.preflight.check_udp_16kb", udp),
        patch("blockchecks.engine.preflight._triage_domain", l3),
    ):
        r = run_preflight(
            ["discord.com"],
            PreflightOptions.from_args(SimpleNamespace(no_preflight=True, timeout=5.0)),
        )
    udp.assert_not_called()
    persist.assert_not_called()
    l3.assert_not_called()
    assert r.triage.udp_blocked is True
    assert r.triage.viable_foolings == ["tcp_ts=-1000"]


@pytest.mark.unit
def test_quick_skips_udp_burst_keeps_prior():
    from types import SimpleNamespace

    prior = TriageProfile(udp_blocked=True, viable_foolings=["tcp_md5"])
    persist = AsyncMock()
    udp = MagicMock(return_value=(False, "answered"))
    with (
        patch("blockchecks.engine.preflight._load_prior_triage", return_value=prior),
        patch("blockchecks.engine.preflight._persist_triage", persist),
        patch("blockchecks.engine.preflight.check_udp_16kb", udp),
        patch("blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "")),
        patch("blockchecks.engine.preflight.run_prolog_tls"),
        patch("blockchecks.engine.preflight._triage_domain"),
        patch("blockchecks.engine.preflight.run_port_block_probe"),
        patch("blockchecks.engine.preflight.print_port_block_report"),
    ):
        r = run_preflight(
            ["discord.com"],
            PreflightOptions.from_args(
                SimpleNamespace(
                    quick=True, timeout=5.0, skip_nfqws2_check=True, skip_dns_audit=True
                ),
                dns_cache=MagicMock(),
            ),
        )
    udp.assert_not_called()
    persist.assert_awaited()
    assert r.triage.udp_blocked is True
    assert r.triage.viable_foolings == ["tcp_md5"]


@pytest.mark.unit
def test_preflight_force_keeps_domain():
    from blockchecks.checkers.tcp_tls import TlsResult

    cache = MagicMock()
    cache.resolve.return_value = ["1.2.3.4"]
    with (
        patch("blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "")),
        patch(
            "blockchecks.engine.preflight.run_prolog_tls",
            return_value=TlsResult(domain="discord.com", success=True, http_status=200),
        ),
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


# options / dns sync / baseline fallback / DNS check / udp16kb
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
    assert o.skip_diagnostics is False


def test_from_args_skip_diagnostics_quick_and_no_preflight():
    from types import SimpleNamespace

    campaign = SimpleNamespace(timeout=5.0)
    assert PreflightOptions.from_args(campaign).skip_diagnostics is False
    quick = PreflightOptions.from_args(SimpleNamespace(quick=True, timeout=5.0))
    assert quick.skip_diagnostics is True
    assert quick.skip_udp_16kb is True
    assert quick.skip_l3_triage is False
    assert quick.skip_persist is False
    none = PreflightOptions.from_args(SimpleNamespace(no_preflight=True, timeout=5.0))
    assert none.skip_diagnostics is True
    assert none.skip_udp_16kb is True
    assert none.skip_l3_triage is True
    assert none.skip_persist is True
    assert none.dpi_diag is False


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


def test_check_udp_16kb_unauthenticated_rtp_not_blocked():
    from blockchecks.engine.preflight import check_udp_16kb

    with (
        patch(
            "blockchecks.engine.preflight._voice_endpoint_candidates",
            return_value=[("1.2.3.4", 50004)],
        ),
        patch(
            "blockchecks.checkers.udp_voice.voice_burst_probe",
            return_value=(
                True,
                5.0,
                "20B STUN after RTP burst (unauthenticated RTP dropped, UDP open)",
            ),
        ),
    ):
        blocked, detail = check_udp_16kb(5.0)
    assert blocked is False
    assert "unauthenticated" in detail or "answered" in detail


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
        patch(
            "blockchecks.engine.preflight.run_prolog_tls",
            return_value=MagicMock(success=False, error="timeout", http_status=0),
        ),
        patch("blockchecks.engine.preflight.run_ip_block_cross_test", return_value=MagicMock()),
        patch("blockchecks.engine.preflight.print_ip_block_report"),
        patch("blockchecks.engine.preflight._triage_domain"),
    ):
        report = asyncio.run(run_preflight_async(["discord.com"], opts))
    assert report.exit_code == 0
    assert report.baseline_ok is True
    assert report.triage is not None
    assert report.triage.voice_ok is True


def test_preflight_wires_dns_prolog_voice_into_triage():
    from blockchecks.checkers.tcp_tls import TlsResult
    from blockchecks.engine.fail_phase import FailPhase

    cache = MagicMock()
    cache.resolve.return_value = ["1.2.3.4"]
    store = MagicMock()
    store.write_dns_audit_log = AsyncMock()
    tls = TlsResult(domain="youtube.com", success=False, http_status=0, error="Connection reset")
    dns_rows = [
        {
            "domain": "youtube.com",
            "tampered": True,
            "udp_ips": "10.0.0.1",
            "doh_ips": "1.2.3.4",
            "verdict": "tampered",
            "doh_server": "https://doh",
        }
    ]
    with (
        patch(
            "blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "iana.org")
        ),
        patch(
            "blockchecks.engine.preflight._audit_domains_parallel",
            new=AsyncMock(return_value=dns_rows),
        ),
        patch("blockchecks.engine.preflight.check_udp_16kb", return_value=(True, "burst dropped")),
        patch("blockchecks.engine.preflight.run_prolog_tls", return_value=tls),
        patch("blockchecks.engine.preflight.run_port_block_probe"),
        patch("blockchecks.engine.preflight.print_port_block_report"),
        patch("blockchecks.engine.preflight.run_ip_block_cross_test"),
        patch("blockchecks.engine.preflight.print_ip_block_report"),
        patch("blockchecks.engine.preflight._triage_domain"),
    ):
        r = run_preflight(
            ["youtube.com"],
            PreflightOptions(
                skip_nfqws2_check=True,
                skip_ip_block=True,
                skip_port_block=True,
                dns_cache=cache,
                store=store,
            ),
        )
    t = r.triage
    assert t is not None
    assert t.dns_hijacked is True
    assert t.rst_at_sni is True
    assert t.handshake_phase == FailPhase.TLS_RST_AT_SNI
    assert t.voice_ok is False
    assert t.udp_blocked is True
    assert t.domain_phases["youtube.com"] == FailPhase.TLS_RST_AT_SNI.value


def test_preflight_diagnostics_fooling_grid():
    from blockchecks.checkers.tcp_tls import TlsResult

    cache = MagicMock()
    cache.resolve.return_value = ["1.2.3.4"]
    cache.primary_ip.return_value = "1.2.3.4"

    def probe(strategy: str):
        if "badsum" in strategy:
            return False, "SSL error 35", 0
        return True, "", 200

    with (
        patch(
            "blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "iana.org")
        ),
        patch(
            "blockchecks.engine.preflight.run_prolog_tls",
            return_value=TlsResult(
                domain="youtube.com", success=False, error="timeout", http_status=0
            ),
        ),
        patch("blockchecks.engine.preflight.check_udp_16kb", return_value=(False, "")),
        patch("blockchecks.engine.preflight._triage_domain"),
        patch("blockchecks.checkers.ttl_probe.probe_ttl") as mock_ttl,
        patch("blockchecks.checkers.fooling_probe.probe_ech_blocked", return_value=True),
        patch("blockchecks.checkers.fooling_probe.probe_http_blocked", return_value=False),
    ):
        from blockchecks.checkers.ttl_probe import TtlProbeResult

        mock_ttl.return_value = TtlProbeResult(server_hops=12, dpi_hops=3, autottl_delta=3)
        r = run_preflight(
            ["youtube.com"],
            PreflightOptions(
                skip_nfqws2_check=True,
                skip_ip_block=True,
                skip_port_block=True,
                skip_dns_audit=True,
                skip_diagnostics=False,
                dns_cache=cache,
                fooling_probe_fn=probe,
            ),
        )
    t = r.triage
    assert t is not None
    assert "tcp_ts=-1000" in t.viable_foolings
    assert "badsum" not in t.viable_foolings
    assert t.server_hops == 12
    assert t.dpi_hops == 3
    assert t.ech_blocked is True
    assert t.http_blocked is False
    assert t.silent_drop_after_sni is True
    assert "stun" in t.viable_blobs


def test_dns_audit_without_store_sets_hijacked():
    from blockchecks.checkers.tcp_tls import TlsResult
    from blockchecks.engine.fail_phase import FailPhase

    cache = MagicMock()
    cache.resolve.return_value = ["1.2.3.4"]
    tls = TlsResult(domain="youtube.com", success=False, http_status=0, error="timeout")
    dns_rows = [
        {
            "domain": "youtube.com",
            "tampered": True,
            "udp_ips": "10.0.0.1",
            "doh_ips": "1.2.3.4",
            "verdict": "tampered",
            "doh_server": "https://doh",
        }
    ]
    with (
        patch(
            "blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "iana.org")
        ),
        patch(
            "blockchecks.engine.preflight._audit_domains_parallel",
            new=AsyncMock(return_value=dns_rows),
        ),
        patch("blockchecks.engine.preflight.check_udp_16kb", return_value=(False, "")),
        patch("blockchecks.engine.preflight.run_prolog_tls", return_value=tls),
        patch("blockchecks.engine.preflight._triage_domain"),
    ):
        r = run_preflight(
            ["youtube.com"],
            PreflightOptions(
                skip_nfqws2_check=True,
                skip_ip_block=True,
                skip_port_block=True,
                dns_cache=cache,
                store=None,
            ),
        )
    assert r.triage is not None
    assert r.triage.dns_hijacked is True
    assert r.triage.handshake_phase == FailPhase.CONNECT_TIMEOUT


def test_live_probe_uses_pf_netns_and_stops():
    import asyncio

    from blockchecks.checkers.ttl_probe import TtlProbeResult
    from blockchecks.engine.preflight import _run_diagnostics

    runner = MagicMock()
    runner.start = AsyncMock()
    runner.stop = AsyncMock()
    runner.test_tcp = AsyncMock(return_value=MagicMock(success=True, error="", http_code=200))
    cache = MagicMock()
    cache.primary_ip.return_value = "1.2.3.4"
    with (
        patch("blockchecks.engine.async_runner.AsyncTestRunner", return_value=runner) as ctor,
        patch("blockchecks.checkers.ttl_probe.probe_ttl") as mock_ttl,
        patch("blockchecks.checkers.fooling_probe.probe_ech_blocked", return_value=None),
        patch("blockchecks.checkers.fooling_probe.probe_http_blocked", return_value=False),
        patch(
            "blockchecks.checkers.fooling_probe.run_fooling_grid_async",
            new=AsyncMock(return_value=MagicMock(viable=["tcp_ts=-1000"])),
        ),
        patch(
            "blockchecks.checkers.fooling_probe.run_split_grid_async",
            new=AsyncMock(return_value="first_byte"),
        ),
        patch(
            "blockchecks.checkers.fooling_probe.run_blob_grid_async",
            new=AsyncMock(return_value=["stun"]),
        ),
    ):
        mock_ttl.return_value = TtlProbeResult(server_hops=12, dpi_hops=3, autottl_delta=3)
        asyncio.run(_run_diagnostics(TriageProfile(), "youtube.com", cache, PreflightOptions()))
    assert ctor.call_args.kwargs["auto_pin"] is False
    assert ctor.call_args.kwargs["netns_base"].startswith("bs-pf-")
    runner.stop.assert_awaited()


def test_handle_triage_reuses_started_runner():
    import asyncio

    from blockchecks.engine.fail_phase import FailPhase
    from blockchecks.service.server import ProbeServer

    runner = MagicMock()
    runner.test_tcp = AsyncMock(return_value=MagicMock(success=True, error="", http_code=200))
    service = MagicMock()
    service.started = True
    service.runner = runner
    service._lock = asyncio.Lock()
    report = MagicMock(triage=TriageProfile(handshake_phase=FailPhase.PASS))
    with (
        patch(
            "blockchecks.engine.preflight.run_preflight_async",
            new=AsyncMock(return_value=report),
        ) as pf,
        patch("blockchecks.engine.async_runner.AsyncTestRunner") as ctor,
    ):
        asyncio.run(ProbeServer(service)._handle_triage({"domain": "youtube.com"}))
    ctor.assert_not_called()
    opts = pf.await_args.args[1]
    assert callable(opts.fooling_probe_fn)


@pytest.mark.unit
def test_apply_ip_block_cdn_keeps_bypassable():
    from blockchecks.checkers.ip_block import IpBlockReport
    from blockchecks.engine.preflight import _apply_ip_block
    from blockchecks.engine.triage import TriageProfile

    report = IpBlockReport("discord.com", "iana.org")
    report.blocked_ips = ["162.159.1.1"]
    report.ip_block_on = ["162.159.1.1"]
    triage = TriageProfile()
    _apply_ip_block(triage, "discord.com", report, is_primary=True)
    assert "discord.com" not in triage.domain_phases
    assert triage.bypassable is True
    assert triage.unbypassable_l3 is False
    assert triage.domain_reports["discord.com"]["ip_blocked"] is False
    assert triage.domain_reports["discord.com"]["sni_block_likely"] is True


@pytest.mark.unit
def test_apply_ip_block_sni_likely_skips_ip_blocked():
    from blockchecks.checkers.ip_block import IpBlockReport
    from blockchecks.engine.preflight import _apply_ip_block
    from blockchecks.engine.triage import TriageProfile

    report = IpBlockReport("example.com", "iana.org")
    report.blocked_ips = ["93.184.216.34"]
    report.ip_block_on = ["93.184.216.34"]
    report.sni_block_likely = True
    triage = TriageProfile()
    triage.domain_phases["example.com"] = "tls_silent_drop_after_sni"
    _apply_ip_block(triage, "example.com", report, is_primary=True)
    assert triage.domain_phases["example.com"] == "tls_silent_drop_after_sni"
    assert triage.unbypassable_l3 is False


@pytest.mark.unit
def test_apply_ip_block_discord_fastly_not_ip_blocked():
    from blockchecks.checkers.ip_block import IpBlockReport
    from blockchecks.engine.preflight import _apply_ip_block
    from blockchecks.engine.triage import TriageProfile

    report = IpBlockReport("dl.discordapp.net", "iana.org")
    report.blocked_ips = ["8.6.112.0", "8.47.69.0"]
    report.ip_block_on = ["8.6.112.0", "8.47.69.0"]
    triage = TriageProfile()
    triage.domain_phases["dl.discordapp.net"] = "tls_silent_drop_after_sni"
    _apply_ip_block(triage, "dl.discordapp.net", report, is_primary=True)
    assert triage.domain_phases["dl.discordapp.net"] == "tls_silent_drop_after_sni"
    assert triage.unbypassable_l3 is False


@pytest.mark.unit
def test_apply_ip_block_google_keeps_bypassable():
    from blockchecks.checkers.ip_block import IpBlockReport
    from blockchecks.engine.preflight import _apply_ip_block
    from blockchecks.engine.triage import TriageProfile

    report = IpBlockReport("youtube.com", "iana.org")
    report.blocked_ips = ["172.217.20.164"]
    report.ip_block_on = ["172.217.20.164"]
    triage = TriageProfile()
    _apply_ip_block(triage, "youtube.com", report, is_primary=True)
    assert triage.unbypassable_l3 is False
    assert triage.domain_reports["youtube.com"]["sni_block_likely"] is True


def test_apply_ip_block_origin_sets_unbypassable():
    from blockchecks.checkers.ip_block import IpBlockReport
    from blockchecks.engine.preflight import _apply_ip_block
    from blockchecks.engine.triage import TriageProfile

    report = IpBlockReport("example.com", "iana.org")
    report.blocked_ips = ["93.184.216.34"]
    report.ip_block_on = ["93.184.216.34"]
    triage = TriageProfile()
    _apply_ip_block(triage, "example.com", report, is_primary=True)
    assert triage.unbypassable_l3 is True
    assert triage.bypassable is False


@pytest.mark.unit
def test_triage_domain_cdn_syn_drop_keeps_bypassable():
    from blockchecks.engine.fail_phase import FailPhase
    from blockchecks.engine.preflight import PreflightOptions, _triage_domain
    from blockchecks.engine.triage import TriageProfile

    report = MagicMock(
        phase=FailPhase.L4_SYN_DROP, tcp_reachable=False, ip="162.159.1.1", port=443
    )
    triage = TriageProfile()
    with patch("blockchecks.checkers.l3_probe.probe_l3", return_value=report):
        _triage_domain(
            triage, "discord.com", ["162.159.1.1"], PreflightOptions(), None, is_primary=True
        )
    assert triage.domain_phases["discord.com"] == FailPhase.L4_SYN_DROP.value
    assert triage.unbypassable_l3 is False
    assert triage.bypassable is True


@pytest.mark.unit
def test_triage_domain_origin_syn_drop_unbypassable():
    from blockchecks.engine.fail_phase import FailPhase
    from blockchecks.engine.preflight import PreflightOptions, _triage_domain
    from blockchecks.engine.triage import TriageProfile

    report = MagicMock(
        phase=FailPhase.L4_SYN_DROP, tcp_reachable=False, ip="93.184.216.34", port=443
    )
    triage = TriageProfile()
    with patch("blockchecks.checkers.l3_probe.probe_l3", return_value=report):
        _triage_domain(
            triage, "example.com", ["93.184.216.34"], PreflightOptions(), None, is_primary=True
        )
    assert triage.unbypassable_l3 is True
    assert triage.l3_phase == FailPhase.L4_SYN_DROP


@pytest.mark.unit
def test_triage_domain_second_ip_live_not_unbypassable():
    from blockchecks.engine.fail_phase import FailPhase
    from blockchecks.engine.preflight import PreflightOptions, _triage_domain
    from blockchecks.engine.triage import TriageProfile

    drop = MagicMock(
        phase=FailPhase.L4_SYN_DROP, tcp_reachable=False, ip="93.184.216.34", port=443
    )
    live = MagicMock(phase=FailPhase.PASS, tcp_reachable=True, ip="93.184.216.35", port=443)

    def _probe(ip, *_a, **_k):
        return drop if ip == "93.184.216.34" else live

    cache = MagicMock()
    cache.primary_ip.return_value = "93.184.216.35"
    triage = TriageProfile()
    with (
        patch("blockchecks.checkers.l3_probe.probe_l3", side_effect=_probe) as l3,
        patch(
            "blockchecks.checkers.curl_probe.run_stream_triage_probe",
            side_effect=RuntimeError("skip"),
        ),
        patch(
            "blockchecks.checkers.curl_probe.run_tls_profile_probe",
            side_effect=RuntimeError("skip"),
        ),
        patch(
            "blockchecks.checkers.quic_raw.probe_quic_initial",
            side_effect=RuntimeError("skip"),
        ),
    ):
        _triage_domain(
            triage,
            "example.com",
            ["93.184.216.34", "93.184.216.35"],
            PreflightOptions(),
            cache,
            is_primary=True,
        )
    assert l3.call_count == 2
    cache.add_pin.assert_called_once_with("example.com", "93.184.216.35")
    assert triage.unbypassable_l3 is False


@pytest.mark.unit
def test_cluster_domain_reports_groups_identical():
    from blockchecks.engine.triage import cluster_domain_reports, clustered_primary_domain

    drop = {"phase": "tls_silent_drop_after_sni", "prolog_ok": False, "silent_drop": True}
    reports = {
        "discord.com": dict(drop),
        "discord.gg": dict(drop),
        "gateway.discord.gg": dict(drop),
        "storage.googleapis.com": {"phase": "pass", "prolog_ok": True},
    }
    clusters = cluster_domain_reports(reports)
    assert clustered_primary_domain(reports) == "discord.com, discord.gg, gateway.discord.gg"
    assert len(clusters) == 2
    assert clusters[1]["primary_domain"] == "storage.googleapis.com"


@pytest.mark.unit
def test_flush_l3_pins_writes_hosts():
    from blockchecks.engine.preflight import _flush_l3_pins

    store = MagicMock()
    cache = MagicMock()
    cache.pins.return_value = {"discord.com": "162.159.1.1", "empty.net": ""}
    _flush_l3_pins(store, cache)
    store.write_hosts.assert_called_once_with({"discord.com": ["162.159.1.1"]})


@pytest.mark.unit
def test_collect_preflight_domains_requires_source():
    from argparse import Namespace

    from blockchecks.cli.commands.preflight import collect_preflight_domains

    domains, rc = collect_preflight_domains(Namespace(domain=None, preset=None, domains_file=None))
    assert rc == 1
    assert domains == []


@pytest.mark.unit
def test_collect_preflight_domains_merges_repeatable_d(tmp_path):
    from argparse import Namespace

    from blockchecks.cli.commands.preflight import collect_preflight_domains

    path = tmp_path / "extra.txt"
    path.write_text("cdn.discordapp.com\n", encoding="utf-8")
    domains, rc = collect_preflight_domains(
        Namespace(
            domain=["discord.com", "discord.gg"],
            preset=None,
            domains_file=str(path),
            allow_unsafe_domains=True,
            list_presets=False,
        )
    )
    assert rc is None
    assert domains == ["discord.com", "discord.gg", "cdn.discordapp.com"]


@pytest.mark.unit
def test_cmd_preflight_runs_without_matrix(monkeypatch):
    import asyncio
    from argparse import Namespace
    from unittest.mock import AsyncMock

    from blockchecks.cli.commands import preflight as pf
    from blockchecks.engine.preflight import PreflightReport

    monkeypatch.setattr("blockchecks.data_block.provider.provider_name", lambda **_k: "testp")
    monkeypatch.setattr(
        pf,
        "prepare_dns_for_run",
        lambda *_a, **_k: (MagicMock(pins=lambda: {}), [], 0),
    )
    monkeypatch.setattr(pf, "_resolve_pin_path", lambda _a: "")
    report = PreflightReport()
    report.exit_code = None
    monkeypatch.setattr(pf, "run_preflight_async", AsyncMock(return_value=report))
    rc = asyncio.run(
        pf.cmd_preflight(
            Namespace(
                domain=["discord.com"],
                preset=None,
                domains_file=None,
                list_presets=False,
                no_secure_dns=True,
                skip_dns_audit=True,
                allow_dns_hijack=True,
                doh_server=None,
                data_block_sync=False,
                timeout=3.0,
            )
        )
    )
    assert rc == 0
    pf.run_preflight_async.assert_awaited_once()
    assert pf.run_preflight_async.await_args.args[0] == ["discord.com"]


@pytest.mark.unit
def test_preflight_json_payload_contract(tmp_path, monkeypatch):
    from blockchecks.cli.commands.preflight import preflight_json_payload
    from blockchecks.engine.preflight import PreflightReport
    from blockchecks.engine.triage import TriageProfile

    class _Store:
        triage_file = tmp_path / "triage.toml"
        hosts_file = tmp_path / "hosts"

    monkeypatch.setattr(
        "blockchecks.cli.commands.preflight._provider_store", lambda: _Store()
    )
    monkeypatch.setattr(
        "blockchecks.data_block.provider.provider_name", lambda **_k: "fryazino"
    )
    report = PreflightReport(
        skip_domains={"ok.example"},
        triage=TriageProfile(voice_ok=False, udp_blocked=True),
    )
    payload = preflight_json_payload(report, exit_code=0, domains=["discord.com"])
    assert payload["ok"] is True
    assert payload["exit_code"] == 0
    assert payload["provider"] == "fryazino"
    assert payload["skip_domains"] == ["ok.example"]
    assert payload["voice_ok"] is False
    assert payload["udp_blocked"] is True
    assert payload["triage_path"].endswith("triage.toml")
    assert payload["triage"]["udp_blocked"] is True


@pytest.mark.unit
def test_cmd_preflight_json_stdout(monkeypatch, capsys):
    import asyncio
    from argparse import Namespace
    from unittest.mock import AsyncMock

    from blockchecks.cli.commands import preflight as pf
    from blockchecks.engine.preflight import PreflightReport
    from blockchecks.engine.triage import TriageProfile

    class _Store:
        triage_file = "/tmp/triage.toml"
        hosts_file = "/tmp/hosts"

    monkeypatch.setattr(pf, "_provider_store", lambda: _Store())
    monkeypatch.setattr("blockchecks.data_block.provider.provider_name", lambda **_k: "testp")
    monkeypatch.setattr(
        pf,
        "prepare_dns_for_run",
        lambda *_a, **_k: (MagicMock(pins=lambda: {}), [], 0),
    )
    monkeypatch.setattr(pf, "_resolve_pin_path", lambda _a: "")
    monkeypatch.setattr(pf, "_maybe_skip_fooling_for_lock", lambda _a: None)
    report = PreflightReport(triage=TriageProfile(voice_ok=True))
    report.exit_code = 0
    monkeypatch.setattr(pf, "run_preflight_async", AsyncMock(return_value=report))
    rc = asyncio.run(
        pf.cmd_preflight(
            Namespace(
                domain=["discord.com"],
                preset=None,
                domains_file=None,
                list_presets=False,
                no_secure_dns=True,
                skip_dns_audit=True,
                allow_dns_hijack=True,
                doh_server=None,
                data_block_sync=False,
                timeout=3.0,
                json=True,
            )
        )
    )
    assert rc == 0
    out = capsys.readouterr().out
    import json

    payload = json.loads(out)
    assert payload["ok"] is True
    assert payload["voice_ok"] is True


@pytest.mark.unit
def test_apply_triage_from_args_missing_file(tmp_path):
    from types import SimpleNamespace

    from blockchecks.engine.preflight import apply_triage_from_args
    from blockchecks.engine.triage import TriageProfile

    args = SimpleNamespace(triage_from=str(tmp_path / "nope.toml"), triage=None)
    apply_triage_from_args(args)
    assert isinstance(args.triage, TriageProfile)
    assert args.triage.voice_ok is False


@pytest.mark.unit
def test_apply_triage_from_args_loads_toml(tmp_path):
    from types import SimpleNamespace

    from blockchecks.data_block.store import ProviderStore
    from blockchecks.engine.preflight import apply_triage_from_args
    from blockchecks.engine.triage import TriageProfile

    store = ProviderStore(tmp_path)
    store.save_triage(TriageProfile(voice_ok=True, udp_blocked=True), primary_domain="discord.com")
    args = SimpleNamespace(triage_from=str(store.triage_file), triage=None)
    apply_triage_from_args(args)
    assert args.triage.voice_ok is True
    assert args.triage.udp_blocked is True


@pytest.mark.unit
def test_run_diagnostics_skips_fooling_grid(monkeypatch):
    import asyncio

    from blockchecks.engine.preflight import PreflightOptions, _run_diagnostics
    from blockchecks.engine.triage import TriageProfile

    live = AsyncMock(return_value=(None, None))
    monkeypatch.setattr("blockchecks.engine.preflight._try_live_strategy_probe", live)
    monkeypatch.setattr(
        "blockchecks.engine.preflight._run_fooling_and_blob_grids",
        AsyncMock(),
    )
    opts = PreflightOptions(skip_fooling_grid=True, timeout=1.0)
    cache = MagicMock()
    cache.primary_ip.return_value = None
    asyncio.run(_run_diagnostics(TriageProfile(), "discord.com", cache, opts))
    live.assert_not_called()


@pytest.mark.unit
def test_maybe_skip_fooling_for_lock(monkeypatch):
    from argparse import Namespace

    from blockchecks.cli.commands.preflight import _maybe_skip_fooling_for_lock

    monkeypatch.setattr(
        "blockchecks.service.run_control.read_active_run",
        lambda: object(),
    )
    args = Namespace()
    _maybe_skip_fooling_for_lock(args)
    assert args.skip_fooling_grid is True
