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


@pytest.mark.asyncio
async def test_custom_list_generator_labels_unique_for_long_strategies():
    """Long custom strategies (common prefix >60 chars) must NOT collide —
    the previous [:60] truncation produced identical labels and broke resume."""
    from blockchecks.engine.generators.custom import CustomListGenerator

    with tempfile.TemporaryDirectory() as d:
        # Two strategies sharing a >60-char prefix but differing in the tail.
        common = "fake:blob=stun:repeats=6:tcp_ts=-1000:ip_ttl="
        p = os.path.join(d, "list_https_tls12.txt")
        with open(p, "w") as f:
            f.write(common + "64\n")
            f.write(common + "128\n")

        gen = CustomListGenerator(base_dir=d)
        items = await gen.generate("tls12", scan_level="full", max_count=10)

    assert len(items) == 2
    assert len({i.label for i in items}) == 2, f"labels collided: {[i.label for i in items]}"
    # labels must encode the differing tail, not truncate to the common prefix
    assert items[0].label != items[1].label


@pytest.mark.asyncio
async def test_generate_udp_voice_protocol_and_filter():
    gen = MatrixGenerator()
    fast = await gen.generate_udp(sources=["standard_udp"], scan_level="fast", max_count=400)
    full = await MatrixGenerator().generate_udp(
        sources=["standard_udp"], scan_level="full", max_count=400
    )
    assert fast and full
    assert all(i.protocol == "udp_voice" for i in fast + full)
    assert all("50000-50100" in i.strategy for i in fast)
    assert len(full) > len(fast)


@pytest.mark.asyncio
async def test_generate_udp_game_not_in_default():
    default = await MatrixGenerator().generate_udp(
        sources=["custom", "standard_udp"], scan_level="single", max_count=80
    )
    assert not any("std_udp_game" in i.label for i in default)
    game = await MatrixGenerator().generate_udp(sources=["game"], scan_level="single", max_count=20)
    assert game
    assert all(i.protocol == "udp_voice" for i in game)
    assert any("std_udp_game" in i.label or "filter-udp=" in i.strategy for i in game)
