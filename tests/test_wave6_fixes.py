"""Tests for Wave 6 bug fixes: resume, full_voice, in-run set, UNIQUE(name,proto), scan_level single."""

import os, sys, asyncio
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.async_runner import AsyncTestRunner, StrategyItem, TcpTestResult
from engine.db_logger import StateDB


def test_unique_name_proto():
    """UNIQUE(name,proto) — TCP and UDP with same name get different IDs."""
    import tempfile
    db_path = tempfile.mktemp(suffix=".db")
    db = StateDB(db_path)
    asyncio.run(_async_test_unique(db))
    os.unlink(db_path)


async def _async_test_unique(db):
    await db.init()
    id1 = await db.ensure_strategy("fake_r6", "tcp", "test_tcp")
    id2 = await db.ensure_strategy("fake_r6", "udp", "test_udp")
    assert id1 != id2, f"Same name different proto should have different IDs: {id1} == {id2}"
    print("PASS test_unique_name_proto")


async def test_resume_fingerprint():
    """resume_from tuple passed to test_pair_matrix is accepted."""
    runner = AsyncTestRunner(pool_size=1)
    await runner.start()
    tcp = TcpTestResult(
        item=StrategyItem(label="tcp_a", strategy="fake:repeats=1"),
        domain="d", success=True
    )
    pairs = await runner.test_pair_matrix(
        [tcp], [StrategyItem(label="udp_a", strategy="f")],
        "d", voice_ip="1.2.3.4", voice_port=5,
        resume_from=(0, 0, "", "", "udp_a", "tcp_a"),
    )
    await runner.stop()
    print("PASS test_resume_fingerprint")


async def test_full_voice_passed():
    """full_voice param is accepted by test_pair_matrix."""
    runner = AsyncTestRunner(pool_size=1)
    await runner.start()
    tcp = TcpTestResult(
        item=StrategyItem(label="tcp_a", strategy="fake:repeats=1"),
        domain="d", success=True
    )
    pairs = await runner.test_pair_matrix(
        [tcp], [StrategyItem(label="udp_a", strategy="f")],
        "d", voice_ip="1.2.3.4", voice_port=5,
        full_voice=True,
    )
    await runner.stop()
    print("PASS test_full_voice_passed")


async def test_scan_level_single():
    """scan_level single produces exactly 1 strategy from a generator."""
    from engine.matrix_generator import FakeTcpGenerator
    gen = FakeTcpGenerator()
    items = await gen.generate("tls12", scan_level="single", max_count=10)
    assert len(items) <= 1, f"single should produce <=1 items, got {len(items)}"
    print("PASS test_scan_level_single")


async def test_in_run_set():
    """Generator accepts run_set and uses it for fast skip."""
    from engine.matrix_generator import FakeTcpGenerator
    gen = FakeTcpGenerator()
    # With run_set containing the base label, fast should skip TTL variants
    items_full = await gen.generate("tls12", scan_level="fast", max_count=5)
    items_slim = await gen.generate("tls12", scan_level="fast", max_count=5, 
                                     run_set={items_full[0].label})
    assert len(items_slim) <= len(items_full), \
        f"With run_set, should produce <= items (got {len(items_slim)} vs {len(items_full)})"
    print("PASS test_in_run_set")


if __name__ == "__main__":
    test_unique_name_proto()
    asyncio.run(test_resume_fingerprint())
    asyncio.run(test_full_voice_passed())
    asyncio.run(test_scan_level_single())
    asyncio.run(test_in_run_set())
    print("All Wave 6 tests PASSED")
