"""Unit tests for the byedpi strategy matrix generator."""

from __future__ import annotations

import asyncio

import pytest

from blockchecks.engine.byedpi_matrix_generator import (
    NATIVE_BYEDPI,
    TRANSLATED_SEEDS,
    ByedpiMatrixGenerator,
)
from blockchecks.engine.matrix_generator import MatrixGenerator

pytestmark = pytest.mark.unit


def _run(gen: ByedpiMatrixGenerator, **kw):
    return asyncio.run(gen.generate(**kw))


def test_registry_contains_byedpi():
    mg = MatrixGenerator()
    assert "byedpi" in mg.REGISTRY
    mg._ensure_registered("byedpi")
    assert isinstance(mg._generators["byedpi"], ByedpiMatrixGenerator)


def test_generate_full_pool():
    items = _run(ByedpiMatrixGenerator(), protocol="tls12")
    assert len(items) > 20
    # no duplicates
    strategies = [it.strategy for it in items]
    assert len(strategies) == len(set(strategies))


def test_http_filters_native_http_lines():
    http_items = _run(ByedpiMatrixGenerator(), protocol="http")
    http_strat = [it.strategy for it in http_items]
    # -M lines are HTTP-only → present in http protocol
    assert any("-M" in s for s in http_strat)
    tls_items = _run(ByedpiMatrixGenerator(), protocol="tls12")
    tls_strat = [it.strategy for it in tls_items]
    assert not any("-M" in s for s in tls_strat)


def test_translated_only_pool():
    items = _run(ByedpiMatrixGenerator(include_native=False), protocol="tls12")
    assert items
    for it in items:
        assert it.label.startswith("byedpi:")


def test_native_only_pool():
    items = _run(ByedpiMatrixGenerator(include_translated=False), protocol="tls12")
    assert items
    for it in items:
        assert it.label.startswith("byedpi_native:")


def test_every_translated_seed_is_translatable():
    for seed in TRANSLATED_SEEDS:
        from blockchecks.engine.byedpi_translator import translate

        assert translate(seed) is not None, f"seed not translatable: {seed!r}"


def test_native_lines_are_nonempty():
    assert NATIVE_BYEDPI
    for line in NATIVE_BYEDPI:
        assert line.strip()
        # all native lines are valid ciadpi-ish CLI (start with - or --)
        assert line.split()[0].startswith("-")


def test_max_count_limits():
    items = _run(ByedpiMatrixGenerator(), protocol="tls12", max_count=5)
    assert len(items) == 5
