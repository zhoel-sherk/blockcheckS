"""MatrixGenerator unit tests (no root)."""
from __future__ import annotations

import os
import tempfile

import pytest

from engine.matrix_generator import (
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


@pytest.mark.asyncio
async def test_single_hostfake():
    gen = HostfakeTcpGenerator()
    items = await gen.generate("tls12", scan_level="single", max_count=10)
    assert len(items) == 1


@pytest.mark.asyncio
async def test_fast_multiple():
    gen = FakeTcpGenerator()
    items = await gen.generate("tls12", scan_level="fast", max_count=50)
    assert len(items) > 1


@pytest.mark.asyncio
async def test_fast_skip_with_run_set():
    gen = FakeTcpGenerator()
    items_full = await gen.generate("tls12", scan_level="fast", max_count=10)
    items_slim = await gen.generate(
        "tls12", scan_level="fast", max_count=10,
        run_set={items_full[0].label},
    )
    assert len(items_slim) <= len(items_full)


@pytest.mark.asyncio
async def test_user_matrix_loads():
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as f:
        f.write("fake:repeats=1\nfake:repeats=6:tcp_ts=-1000\n")
        path = f.name
    try:
        gen = UserMatrixGenerator(path)
        items = await gen.generate("tls12")
        assert len(items) == 2
    finally:
        os.unlink(path)


@pytest.mark.asyncio
async def test_generate_tcp_from_sources():
    mg = MatrixGenerator()
    items = await mg.generate_tcp(sources=["fake"], max_count=5, run_set=set())
    assert len(items) > 0
