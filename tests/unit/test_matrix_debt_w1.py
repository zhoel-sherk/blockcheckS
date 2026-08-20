"""Wave1 matrix debt: repeats=4, TTL overflow, flowseal in full defaults."""

from __future__ import annotations

import pytest

from blockchecks.engine.generators.standard import (
    ALL_REPEATS,
    ALL_TTL,
    FAST_REPEATS,
    REPEATS_VALUES,
    StandardGenerator,
)
from blockchecks.main import build_arg_parser


@pytest.mark.unit
def test_repeats_four_in_matrix_axes():
    assert 4 in REPEATS_VALUES
    assert 4 in ALL_REPEATS
    assert 4 in FAST_REPEATS


@pytest.mark.unit
def test_ttl_values_within_byte_range():
    assert 256 not in ALL_TTL
    assert 512 not in ALL_TTL
    assert max(ALL_TTL) <= 255
    assert min(ALL_TTL) >= 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_standard_fake_full_emits_repeats4_without_ttl_overflow():
    gen = StandardGenerator(strategy_types=["fake"])
    items = await gen.generate("tls12", scan_level="full", max_count=5000)
    strategies = "\n".join(i.strategy for i in items)
    assert "repeats=4" in strategies
    assert "ip_ttl=256" not in strategies
    assert "ip_ttl=512" not in strategies


@pytest.mark.unit
def test_full_tcp_sources_default_includes_flowseal():
    p = build_arg_parser()
    ns = p.parse_args([])
    assert "flowseal" in ns.tcp_sources.split(",")
