"""StrategyParams validation + families decomposition parity tests."""

from __future__ import annotations

import asyncio

import pytest

from blockchecks.engine.generators.families._helpers import (
    StrategyParams,
    _static_numeric_split,
    _ttl_clause,
    _with_ack_drop,
    _with_send_md5,
    cmd_label,
    emit_rows,
    expand_axes,
    required_foolings,
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
def test_ttl_clause_keeps_zero():
    assert _ttl_clause(0) == ":ip_ttl=0"
    assert _ttl_clause(None) == ""
    assert _ttl_clause("") == ""
    assert _ttl_clause("-1,3-20") == ":ip_autottl=-1,3-20"


@pytest.mark.unit
def test_required_foolings_drops_empty():
    assert required_foolings(["tcp_ts=-1000", "", "tcp_md5"]) == ("tcp_ts=-1000", "tcp_md5")


@pytest.mark.unit
def test_expand_axes_product():
    rows = expand_axes(
        {"a": [1, 2], "b": ["x"]},
        lambda d: (f"{d['a']}{d['b']}", f"s{d['a']}"),
    )
    assert rows == [("1x", "s1"), ("2x", "s2")]


@pytest.mark.unit
def test_emit_rows_stops_on_single():
    items, seen = [], set()
    added = []

    def add(items_, seen_, label, strat, protocol="tls12"):
        added.append((label, strat, protocol))
        items_.append(label)
        seen_.add(strat)

    assert emit_rows(add, items, seen, "single", [("a", "s1"), ("b", "s2")]) is True
    assert added == [("a", "s1", "tls12")]
    assert emit_rows(add, items, seen, "fast", [("c", "s3")]) is False
    assert added[-1] == ("c", "s3", "tls12")


@pytest.mark.unit
def test_cmd_label_same_truncated_prefix_differs():
    """Two cmds that share a truncated prefix must still get distinct names."""
    prefix = "std_fake_google_r6_tlsmod=rnd,dupsid,sni=www"  # [:20] of a long tls_mod
    cmd_a = "fake:blob=google:repeats=6:tls_mod=rnd,dupsid,sni=www.google.com"
    cmd_b = "fake:blob=google:repeats=6:tls_mod=rnd,dupsid,sni=www.youtube.com"
    name_a, name_b = cmd_label(prefix, cmd_a), cmd_label(prefix, cmd_b)
    assert name_a != name_b
    assert name_a.startswith(f"{prefix}_")
    assert name_b.startswith(f"{prefix}_")
    assert name_a.rsplit("_", 1)[-1] != name_b.rsplit("_", 1)[-1]
    assert len(name_a.rsplit("_", 1)[-1]) == 6
    assert cmd_label(prefix, cmd_a) == name_a  # stable


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


@pytest.mark.unit
@pytest.mark.parametrize("fam", ["hostfake", "fakedsplit", "fakeddisorder"])
def test_hidden_fake_families_require_fooling(fam):
    async def _run():
        return await StandardGenerator(strategy_types=[fam]).generate(
            protocol="tls12", scan_level="fast", max_count=400
        )

    items = asyncio.run(_run())
    assert items
    assert not any("_nofool" in it.label for it in items)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_fake_max_one_starts_with_tcp_ts_not_ipv6_extra():
    items = await StandardGenerator(strategy_types=["fake"]).generate(
        protocol="tls12", scan_level="fast", max_count=1
    )
    assert items
    assert "tcp_ts=-1000" in items[0].strategy
    assert "ip6_hopbyhop" not in items[0].strategy


@pytest.mark.unit
@pytest.mark.asyncio
async def test_fake_keeps_tcp_ts_when_grid_found_other_fooling():
    from blockchecks.engine.triage import TriageProfile

    triage = TriageProfile(
        viable_foolings=["tcp_md5"],
        viable_blobs=["stun"],
        dead_foolings=["badsum"],
    )
    items = await StandardGenerator(strategy_types=["fake"]).generate(
        protocol="tls12", scan_level="fast", max_count=20, triage=triage
    )
    assert items
    assert any("tcp_ts=-1000" in i.strategy for i in items)
    assert not any("badsum" in i.strategy for i in items)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_generate_keeps_ipfrag_tcp_alias_on_capped_round_robin():
    """Resolved alias must survive the capped round-robin path (not dropped as missing key)."""
    gen = StandardGenerator(strategy_types=["fake", "ipfrag_tcp"])
    items = await gen.generate(protocol="tls12", scan_level="fast", max_count=20)
    joined = "\n".join(f"{i.label} {i.strategy}" for i in items)
    assert "ipfrag" in joined or "tcp_ipfrag" in joined
