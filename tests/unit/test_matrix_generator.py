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
    assert items[0].label.startswith("std_fake_")
    assert items[0].strategy.startswith("fake:blob=")
    assert ":repeats=" in items[0].strategy


@pytest.mark.asyncio
async def test_single_hostfake():
    gen = HostfakeTcpGenerator()
    items = await gen.generate("tls12", scan_level="single", max_count=10)
    assert len(items) == 1
    assert items[0].label.startswith("std_hf_")
    assert "hostfakesplit" in items[0].strategy
    assert "nofool" not in items[0].label
    assert any(tok in items[0].strategy for tok in ("tcp_ts=-1000", "tcp_md5", "badsum"))


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
    skip_label = next(
        it.label
        for it in items_full
        if any(other.label.startswith(f"{it.label}_ttl") for other in items_full)
    )
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
async def test_custom_list_colon_vs_space_same_prefix_differs():
    """Sanitizing ':' and ' ' to '_' used to collide across family-style cmds."""
    from blockchecks.engine.generators.custom import CustomListGenerator

    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "list_https_tls12.txt")
        with open(p, "w") as f:
            f.write("fake blob=stun:repeats=6\n")
            f.write("fake:blob=stun:repeats=6\n")
        items = await CustomListGenerator(base_dir=d).generate(
            "tls12", scan_level="full", max_count=10
        )

    assert [i.strategy for i in items] == [
        "fake blob=stun:repeats=6",
        "fake:blob=stun:repeats=6",
    ]
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
    from blockchecks.engine.conf_builder import build_filter_lines

    voice_filters = "\n".join(build_filter_lines("udp_voice"))
    assert "50000-50100" in voice_filters
    assert any("discord" in i.strategy.lower() for i in fast)
    assert all("fake:blob=" in i.strategy for i in fast)
    assert all("--filter-udp=" not in i.strategy for i in fast)
    assert len(full) > len(fast)


@pytest.mark.asyncio
async def test_generate_udp_game_not_in_default():
    default = await MatrixGenerator().generate_udp(
        sources=["custom", "standard_udp"], scan_level="single", max_count=80
    )
    assert not any("std_udp_game" in i.label for i in default)
    game = await MatrixGenerator().generate_udp(sources=["game"], scan_level="single", max_count=20)
    assert game
    assert all(i.protocol == "udp_game" for i in game)
    assert any("std_udp_game" in i.label for i in game)
    assert all("fake:blob=" in i.strategy for i in game)


@pytest.mark.asyncio
async def test_generate_udp_skips_when_voice_ok():
    from blockchecks.engine.triage import TriageProfile

    items = await MatrixGenerator().generate_udp(
        sources=["standard_udp"],
        triage=TriageProfile(voice_ok=True, udp_blocked=False),
    )
    assert items == []
    still = await MatrixGenerator().generate_udp(
        sources=["standard_udp"],
        scan_level="single",
        max_count=5,
        triage=TriageProfile(voice_ok=True, udp_blocked=True),
    )
    assert still


@pytest.mark.asyncio
async def test_user_matrix_skips_triage_prune(tmp_path):
    from blockchecks.engine.triage import TriageProfile

    matrix = tmp_path / "m.txt"
    matrix.write_text("fake:blob=stun:repeats=6:tcp_ts=-1000\n")
    profile = TriageProfile(viable_foolings=["tcp_md5"], viable_blobs=["tls_clienthello"])
    items = await MatrixGenerator().generate_tcp(
        sources=["custom"],
        user_matrix=str(matrix),
        triage=profile,
        max_count=10,
        scan_level="fast",
    )
    assert len(items) == 1
    assert "stun" in items[0].strategy


@pytest.mark.asyncio
async def test_user_matrix_udp_keeps_tcp_ts(tmp_path):
    """UDP matrix must keep ``tcp_ts`` fooling and still drop TCP-profile CLI."""
    matrix = tmp_path / "m.txt"
    matrix.write_text(
        "fake:blob=stun:repeats=6:tcp_ts=-1000\n"
        "--filter-tcp=443\\nfake:blob=stun:repeats=6\n"
        "--qnum=200\\nfake:blob=stun:repeats=1\n",
        encoding="utf-8",
    )
    items = await UserMatrixGenerator(str(matrix)).generate("udp_voice", max_count=50)
    assert any("tcp_ts=-1000" in i.strategy for i in items)
    assert not any("--filter-tcp" in i.strategy.lower() for i in items)
    assert not any("--qnum=200" in i.strategy.lower() for i in items)


@pytest.mark.asyncio
async def test_user_matrix_mixed_tcp_udp_file(tmp_path):
    """TCP lua-desync with tcp_ack must not occupy the UDP max_count slice."""
    tcp = [
        f"fake:blob=4pda:repeats={i}:tcp_ack=-66000:tcp_ts_up:ip_ttl=7" for i in range(1, 51)
    ]
    udp = [
        f"--filter-udp=50000-50100 --lua-desync=fake:blob=discord_udp:repeats={n}"
        for n in (6, 3, 12, 1, 2, 4)
    ]
    matrix = tmp_path / "champions.txt"
    matrix.write_text("\n".join([*tcp, *udp]) + "\n", encoding="utf-8")
    tcp_items = await MatrixGenerator().generate_tcp(
        user_matrix=str(matrix), max_count=50, scan_level="full"
    )
    udp_items = await MatrixGenerator().generate_udp(
        user_matrix=str(matrix), max_count=50, scan_level="full"
    )
    assert len(tcp_items) == 50
    assert len(udp_items) == 6
    assert all("tcp_ack" not in i.strategy for i in udp_items)
    assert all("--filter-udp" in i.strategy for i in udp_items)


@pytest.mark.asyncio
async def test_user_matrix_udp_section_keeps_tcp_fooling(tmp_path, caplog):
    matrix = tmp_path / "m.txt"
    matrix.write_text(
        "# --- UDP ---\n"
        "fake:blob=google:repeats=6:tcp_ack=-66000:tcp_ts_up\n",
        encoding="utf-8",
    )
    items = await UserMatrixGenerator(str(matrix)).generate("udp_voice", max_count=10)
    assert len(items) == 1
    assert "tcp_ack" in items[0].strategy
    tcp_items = await UserMatrixGenerator(str(matrix)).generate("tls12", max_count=10)
    assert tcp_items == []


@pytest.mark.asyncio
async def test_generate_udp_user_matrix_keeps_when_voice_ok(tmp_path):
    from blockchecks.engine.triage import TriageProfile

    matrix = tmp_path / "m.txt"
    matrix.write_text(
        "--filter-udp=50000-50100 --lua-desync=fake:blob=discord_udp:repeats=6\n",
        encoding="utf-8",
    )
    items = await MatrixGenerator().generate_udp(
        user_matrix=str(matrix),
        triage=TriageProfile(voice_ok=True, udp_blocked=False),
        max_count=10,
    )
    assert len(items) == 1
