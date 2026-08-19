"""TriageProfile + generator-pruning tests (Phase 1-5 + TLS fingerprint)."""

from __future__ import annotations

import pytest

from blockchecks.engine.fail_phase import FailPhase
from blockchecks.engine.generators.standard import (
    StandardGenerator,
    _static_numeric_split,
)
from blockchecks.engine.triage import TriageProfile


@pytest.mark.unit
def test_triage_bypassable_flags():
    t = TriageProfile()
    assert t.bypassable is True
    assert t.requires_window_clamp is False

    t2 = TriageProfile(unbypassable_l3=True)
    assert t2.bypassable is False

    t3 = TriageProfile(stall_phase=FailPhase.DATA_STALL_16K)
    assert t3.requires_window_clamp is True


@pytest.mark.unit
def test_triage_postquantum_and_fingerprint():
    t = TriageProfile(client_hello_len=1740, requires_postquantum_awareness=True)
    assert t.prefer_contextual_split is True

    t2 = TriageProfile(is_tls_fingerprint_blocked=True)
    assert t2.l7_impersonate_sufficient is True


@pytest.mark.unit
def test_triage_to_dict_and_context():
    t = TriageProfile(
        dns_hijacked=True,
        client_hello_len=1740,
        requires_postquantum_awareness=True,
        fingerprint_pass={"chrome124": False, "firefox_120": True},
    )
    d = t.to_dict()
    assert d["dns_hijacked"] is True
    assert d["requires_postquantum_awareness"] is True
    assert d["fingerprint_pass"]["firefox_120"] is True
    c = t.to_context()
    assert c["dns_hijacked"] == 1
    assert c["fp_blocked"] == 0


@pytest.mark.unit
def test_static_numeric_split_heuristic():
    assert _static_numeric_split("multisplit:pos=2:seqovl=1") is True
    assert _static_numeric_split("multisplit:pos=1,midsld:seqovl=1") is False
    assert _static_numeric_split("multisplit:pos=sniext+1:seqovl=1") is False
    assert _static_numeric_split("hostfakesplit:nofake2") is False


@pytest.mark.unit
@pytest.mark.asyncio
async def test_generator_prunes_l3_block():
    g = StandardGenerator(strategy_types=["multisplit"])
    items = await g.generate(
        protocol="tls12",
        scan_level="full",
        max_count=100,
        triage=TriageProfile(unbypassable_l3=True),
    )
    assert items == []


@pytest.mark.unit
@pytest.mark.asyncio
async def test_generator_prunes_static_splits_on_pq():
    g = StandardGenerator(strategy_types=["multisplit"])
    triage = TriageProfile(client_hello_len=1740, requires_postquantum_awareness=True)
    items = await g.generate(
        protocol="tls12",
        scan_level="full",
        max_count=2000,
        triage=triage,
    )
    assert items
    # no purely-numeric split survives post-quantum pruning
    assert not any(_static_numeric_split(i.strategy) for i in items)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_generator_triage_none_compatible():
    g = StandardGenerator(strategy_types=["multisplit"])
    items = await g.generate(protocol="tls12", scan_level="full", max_count=100)
    assert items
