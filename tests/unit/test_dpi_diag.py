"""Optional --dpi-diag probes (dpi-checkers / dpi-detector), isolated from default preflight."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from blockchecks.checkers.dpi_diag.classify import classify_stage
from blockchecks.checkers.dpi_diag.dns_as import as_org_mismatches, cgnat_ips
from blockchecks.checkers.dpi_diag.probes import (
    probe_cidr_whitelist,
    probe_fat_keepalive,
    probe_l4_25,
    probe_siberian,
    probe_sni_whitelist,
)
from blockchecks.checkers.dpi_diag.runner import DpiDiagReport, apply_overlay
from blockchecks.engine.preflight import PreflightOptions
from blockchecks.engine.triage import TriageProfile

pytestmark = [pytest.mark.unit]


def test_classify_stage_tokens():
    assert classify_stage("certificate verify failed") == "tls_mitm"
    assert classify_stage("wrong_version_number") == "tls_spoof"
    assert classify_stage("unrecognized name") == "tls_alert"
    assert classify_stage("timed out", stage="tcp_connect") == "syn_drop"
    assert classify_stage("") == "ok"


def test_as_org_and_cgnat():
    rows = [
        {"domain": "discord.com", "doh_ips": "1.2.3.4"},
        {"domain": "youtube.com", "doh_ips": "142.250.1.1"},
        {"domain": "x.com", "udp_ips": "100.64.1.8"},
    ]
    assert as_org_mismatches(rows) == ["discord.com"]
    assert cgnat_ips(rows) == ["100.64.1.8"]


def test_sni_whitelist_injectable():
    hits = probe_sni_whitelist(
        "162.159.1.1",
        candidates=("ya.ru", "evil.test"),
        get_fn=lambda sni, _ip, _t: sni == "ya.ru",
    )
    assert hits == ["ya.ru"]


def test_l4_25_handshake_failure_inconclusive(monkeypatch):
    def _fail(*_a, **_k):
        raise OSError("connection timed out")

    monkeypatch.setattr("blockchecks.checkers.dpi_diag.probes.socket.create_connection", _fail)
    l4 = probe_l4_25("h", ip="1.1.1.1")
    assert l4["ok"] is False
    assert l4["detected"] is None
    assert l4["packets"] == 0


def test_fat_l4_siberian_cidr_hooks():
    fat = probe_fat_keepalive("h", "1.1.1.1", request_fn=lambda i: i < 3, chunks=5, pad=100)
    assert fat == {"ok": False, "detected": True, "stall_at_bytes": 300}
    assert probe_fat_keepalive("h", "1.1.1.1", request_fn=lambda _i: False, chunks=3)["detected"] is False
    sent: list[int] = []
    l4 = probe_l4_25("h", total=10, chunk=2, send_fn=lambda b: sent.append(len(b)))
    assert l4["ok"] is True and l4["detected"] is False and l4["packets"] == 5 and sent == [2, 2, 2, 2, 2]
    sib = probe_siberian(
        "discord.com",
        "1.1.1.1",
        handshake_fn=lambda sni, _ip, _t: sni == "discord.com",
    )
    assert sib is True
    assert probe_cidr_whitelist(head_fn=lambda url, _t: "ya.ru" in url) is True
    assert probe_cidr_whitelist(head_fn=lambda _u, _t: True) is False


def test_apply_overlay_sets_hosts_without_cgnat_sinkhole():
    t = TriageProfile()
    apply_overlay(
        t,
        DpiDiagReport(sni_whitelist=["ya.ru"], cgnat_sinkhole=["100.64.0.1"]),
    )
    assert t.viable_hosts == ["ya.ru"]
    assert t.dns_sinkhole is False
    assert t.dpi_diag["cgnat_sinkhole"] == ["100.64.0.1"]
    assert t.dpi_diag["sni_whitelist"] == ["ya.ru"]


def test_from_args_dpi_diag_off_by_default_and_no_preflight():
    assert PreflightOptions.from_args(SimpleNamespace(timeout=5.0)).dpi_diag is False
    on = PreflightOptions.from_args(SimpleNamespace(timeout=5.0, dpi_diag=True))
    assert on.dpi_diag is True
    blocked = PreflightOptions.from_args(SimpleNamespace(timeout=5.0, dpi_diag=True, no_preflight=True))
    assert blocked.dpi_diag is False


@pytest.mark.asyncio
async def test_preflight_skips_dpi_diag_network_when_flag_off():
    from blockchecks.engine.preflight import run_preflight_async

    with (
        patch("blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "")),
        patch("blockchecks.engine.preflight.check_udp_16kb", return_value=(False, "")),
        patch("blockchecks.engine.preflight.run_prolog_tls"),
        patch("blockchecks.engine.preflight._triage_domain"),
        patch("blockchecks.checkers.dpi_diag.runner.run_dpi_diag", new_callable=AsyncMock) as diag,
    ):
        await run_preflight_async(
            ["discord.com"],
            PreflightOptions(
                skip_nfqws2_check=True,
                skip_dns_audit=True,
                skip_ip_block=True,
                skip_prolog=True,
                skip_udp_16kb=True,
            ),
        )
    diag.assert_not_called()


@pytest.mark.asyncio
async def test_preflight_clears_sticky_hosts_without_dpi_diag():
    from blockchecks.engine.preflight import run_preflight_async

    prior = TriageProfile(viable_hosts=["ozon.ru", "ya.ru"])
    with (
        patch("blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "")),
        patch("blockchecks.engine.preflight.check_udp_16kb", return_value=(False, "")),
        patch("blockchecks.engine.preflight.run_prolog_tls"),
        patch("blockchecks.engine.preflight._triage_domain"),
        patch("blockchecks.engine.preflight._load_prior_triage", return_value=prior),
        patch("blockchecks.checkers.dpi_diag.runner.run_dpi_diag", new_callable=AsyncMock),
    ):
        report = await run_preflight_async(
            ["discord.com"],
            PreflightOptions(
                skip_nfqws2_check=True,
                skip_dns_audit=True,
                skip_ip_block=True,
                skip_prolog=True,
                skip_udp_16kb=True,
            ),
        )
    assert report.triage.viable_hosts == []


def test_hostfake_emits_viable_hosts():
    import asyncio

    from blockchecks.engine.generators.standard import StandardGenerator

    triage = TriageProfile(viable_hosts=["ozon.ru"], viable_foolings=["tcp_ts=-1000"])
    items = asyncio.run(
        StandardGenerator(strategy_types=["hostfake"]).generate(
            protocol="tls12", scan_level="fast", max_count=50, triage=triage
        )
    )
    assert any("host=ozon.ru" in i.strategy for i in items)
