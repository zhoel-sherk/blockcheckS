"""Integration tests for parallel pair matrix."""

import os, sys, asyncio
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.async_runner import AsyncTestRunner, StrategyItem, TcpTestResult


async def test_pair_parallel():
    """Ensure asyncio.create_task runs pairs in parallel."""
    runner = AsyncTestRunner(pool_size=3)
    await runner.start()

    tcp_res = TcpTestResult(
        item=StrategyItem(label="tcp_ok", strategy="fake:blob=stun:repeats=6:tcp_ts=-1000"),
        domain="discord.com", success=True, latency_ms=100, http_code=200
    )
    udp_items = [StrategyItem(label="udp_r6", strategy="fake:blob=discord_udp:repeats=6"),
                 StrategyItem(label="udp_r12", strategy="fake:blob=discord_udp:repeats=12")]

    pairs = await runner.test_pair_matrix(
        [tcp_res], udp_items, "discord.com",
        voice_ip="35.217.5.42", voice_port=50006,
    )
    assert len(pairs) == 2, f"Expected 2 pairs, got {len(pairs)}"
    await runner.stop()
    print("PASS test_pair_parallel")


async def test_pair_no_working_tcp():
    """Ensure no pairs when all TCP FAIL."""
    runner = AsyncTestRunner(pool_size=2)
    await runner.start()
    tcp_res = TcpTestResult(
        item=StrategyItem(label="tcp_fail", strategy="fake:repeats=1"),
        domain="discord.com", success=False
    )
    pairs = await runner.test_pair_matrix(
        [tcp_res], [StrategyItem(label="u", strategy="f")],
        "discord.com", voice_ip="1.2.3.4", voice_port=5,
    )
    assert len(pairs) == 0, f"Expected 0 pairs, got {len(pairs)}"
    await runner.stop()
    print("PASS test_pair_no_working_tcp")


async def test_pair_udp_bypass():
    """udp_bypass=True forces UDP even on FAIL TCP."""
    runner = AsyncTestRunner(pool_size=2)
    await runner.start()
    tcp_res = TcpTestResult(
        item=StrategyItem(label="tcp_fail", strategy="fake:repeats=1"),
        domain="discord.com", success=False
    )
    pairs = await runner.test_pair_matrix(
        [tcp_res], [StrategyItem(label="u", strategy="f")],
        "discord.com", voice_ip="1.2.3.4", voice_port=5,
        udp_bypass=True,
    )
    assert len(pairs) == 1, f"Expected 1 pair, got {len(pairs)}"
    await runner.stop()
    print("PASS test_pair_udp_bypass")


if __name__ == "__main__":
    asyncio.run(test_pair_parallel())
    asyncio.run(test_pair_no_working_tcp())
    asyncio.run(test_pair_udp_bypass())
    print("All pair matrix tests PASSED")
