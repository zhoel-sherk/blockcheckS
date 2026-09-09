from __future__ import annotations

import pytest


@pytest.mark.unit
def test_multisplit_carrier_strategies_generated():
    """BC2 25-fake payload-replacement carrier (AUDIT §6.2 P2)."""
    import asyncio

    from blockchecks.engine.generators.standard import StandardGenerator

    g = StandardGenerator(strategy_types=["multisplit"])
    rows = asyncio.run(g.generate(scan_level="fast", max_count=100000))
    carriers = [it.strategy for it in rows if it.strategy.startswith("multisplit:blob=")]
    assert any(s == "multisplit:blob=stun:pos=2" for s in carriers)
    assert any(s == "multisplit:blob=stun:pos=2:nodrop" for s in carriers)
    assert any(":pos=midsld" in s for s in carriers)
    # no null-blob carrier (replacement with an empty payload is meaningless)
    assert not any("blob=0x00000000" in s for s in carriers)


@pytest.mark.unit
def test_multidisorder_legacy_family_with_marker_seqovl():
    """Upstream §multidisorder_legacy: seqovl IS a marker here (unlike the
    plain multidisorder, manual.md 'seqovl - число')."""
    import asyncio

    from blockchecks.engine.generators.standard import StandardGenerator

    g = StandardGenerator(strategy_types=["multidisorder_legacy"])
    rows = asyncio.run(g.generate(scan_level="fast", max_count=100000))
    legacy = [it.strategy for it in rows if "multidisorder_legacy" in it.strategy]
    assert legacy, "no multidisorder_legacy strategies generated"
    assert any(":seqovl=midsld-1" in s for s in legacy)
    assert any(":seqovl=1:" in s or ":seqovl=1\n" in s or s.endswith(":seqovl=1") for s in legacy)


@pytest.mark.unit
def test_method2_positions_dropped_from_tls_kept_for_http_axis():
    """§6.4: method+* only on http_req — TLS generation must drop them."""
    from blockchecks.engine.generators.standard import _filter_positions_for_protocol

    positions = ["1", "method+2", "method+2,midsld", "midsld"]
    tls = _filter_positions_for_protocol(positions, "tls12")
    assert "method+2" not in tls and "method+2,midsld" not in tls
    http = _filter_positions_for_protocol(positions, "http")
    assert "method+2" in http and "method+2,midsld" in http


@pytest.mark.unit
def test_tcpseg_seqovl_companion_and_0m1_position():
    """BC2 15-misc: pos=0,-1 + numeric seqovl; pos=0,method+2 (http only)."""
    from blockchecks.engine.family_axes import FAMILY_AXES

    axes = FAMILY_AXES["tcpseg"]
    assert "0,-1" in axes["positions"]
    assert "0,method+2" in axes["positions"]
    assert axes["seqovl_positions"] == ["0,-1"]
    assert list(axes["seqovl"]) == [1]
