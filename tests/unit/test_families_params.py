"""StrategyParams validation + families decomposition parity tests."""

from __future__ import annotations

import asyncio

import pytest

from blockchecks.engine.generators.families._helpers import (
    StrategyParams,
    _static_numeric_split,
    _with_ack_drop,
    _with_send_md5,
)
from blockchecks.engine.generators.standard import StandardGenerator


@pytest.mark.unit
def test_strategy_params_normalizes_types():
    p = StrategyParams.from_family(
        {"repeats": [6, 3], "foolings": ["tcp_ts=-1000", ""], "ack_drop": True}
    )
    assert p.repeats == (6, 3)
    assert p.foolings == ("tcp_ts=-1000", "")
    assert p.ack_drop is True
    assert p.send_md5 is False
    assert p.ttl_static == ()


@pytest.mark.unit
def test_strategy_params_defaults_empty_repeats():
    p = StrategyParams.from_family({})
    assert p.repeats == (6,)  # fallback
    assert p.foolings == ("",)


@pytest.mark.unit
def test_static_numeric_split_classifier():
    assert _static_numeric_split("multisplit:pos=2") is True
    assert _static_numeric_split("multisplit:pos=1,midsld") is False
    assert _static_numeric_split("multisplit:pos=sniext+1") is False
    assert _static_numeric_split("fake:blob=stun:repeats=6") is False


@pytest.mark.unit
def test_ackdrop_sendmd5_helpers():
    assert "pktmod:ip_ttl=1" in _with_ack_drop("fake:repeats=6")
    assert "send:tcp_md5" in _with_send_md5("fake:repeats=6:tcp_md5")


@pytest.mark.unit
def test_standard_generator_family_mixins_present():
    """All _FAMILY_EXPANDERS targets resolve to a real method (mixin wiring)."""
    gen = StandardGenerator(strategy_types=["all"])
    for family_name, method in gen._FAMILY_EXPANDERS.items():
        assert hasattr(gen, method), f"{family_name} -> {method} missing"
        assert callable(getattr(gen, method))


@pytest.mark.unit
@pytest.mark.parametrize(
    "protocol,scan_level",
    [
        ("tls12", "fast"),
        ("tls12", "full"),
        ("http", "fast"),
        ("quic", "fast"),
        ("udp_voice", "fast"),
    ],
)
def test_standard_generator_smoke(protocol, scan_level):
    """Generation produces items for every protocol gate after decomposition."""

    async def _run():
        return await StandardGenerator(strategy_types=["all"]).generate(
            protocol=protocol, scan_level=scan_level, max_count=50
        )

    items = asyncio.run(_run())
    assert isinstance(items, list)
    for it in items:
        assert it.strategy, "empty strategy"
        assert it.label, "empty label"
