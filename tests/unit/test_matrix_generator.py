"""MatrixGenerator unit tests (no root)."""

from __future__ import annotations

import os
import tempfile

import pytest

from blockchecks.engine.matrix_generator import (
    FakeTcpGenerator,
    HostfakeTcpGenerator,
    MatrixGenerator,
    UserMatrixGenerator,
)

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_single_one_per_generator():
    gen = FakeTcpGenerator()
    items = await gen.generate("tls12", scan_level="single", max_count=10)
    assert len(items) == 1
    assert items[0].label == "fake_stun_r6_tcp_ts=-1000"
    assert items[0].strategy == "fake:blob=stun:repeats=6:tcp_ts=-1000"


@pytest.mark.asyncio
async def test_single_hostfake():
    gen = HostfakeTcpGenerator()
    items = await gen.generate("tls12", scan_level="single", max_count=10)
    assert len(items) == 1
    assert items[0].label == "hf_nofake2_nofool"
    assert items[0].strategy == "hostfakesplit:nofake2:repeats=1"


@pytest.mark.asyncio
async def test_fast_multiple():
    gen = FakeTcpGenerator()
    items = await gen.generate("tls12", scan_level="fast", max_count=50)
    assert len(items) > 1
    assert all(i.strategy.startswith("fake:blob=") for i in items)
    assert len({i.label for i in items}) == len(items)


@pytest.mark.asyncio
async def test_fast_skip_with_run_set():
    """Known-working label skips TTL expansions (fast mode), shrinking the matrix."""
    gen = FakeTcpGenerator()
    items_full = await gen.generate("tls12", scan_level="fast", max_count=10_000)
    assert items_full
    skip_label = items_full[0].label
    assert any(i.label.startswith(f"{skip_label}_ttl") for i in items_full)
    items_slim = await gen.generate(
        "tls12",
        scan_level="fast",
        max_count=10_000,
        run_set={skip_label},
    )
    assert items_slim
    assert skip_label in {i.label for i in items_slim}  # base kept
    assert not any(i.label.startswith(f"{skip_label}_ttl") for i in items_slim)
    assert len(items_slim) < len(items_full)


@pytest.mark.asyncio
async def test_user_matrix_loads():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write("fake:repeats=1\nfake:repeats=6:tcp_ts=-1000\n")
        path = f.name
    try:
        gen = UserMatrixGenerator(path)
        items = await gen.generate("tls12")
        assert [i.strategy for i in items] == [
            "fake:repeats=1",
            "fake:repeats=6:tcp_ts=-1000",
        ]
    finally:
        os.unlink(path)


@pytest.mark.asyncio
async def test_generate_tcp_from_sources():
    mg = MatrixGenerator()
    items = await mg.generate_tcp(sources=["fake"], max_count=5, run_set=set())
    assert len(items) > 0
    assert all("fake:" in i.strategy for i in items)
    assert len({i.label for i in items}) == len(items)
