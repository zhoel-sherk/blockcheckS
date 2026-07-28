"""Tests for parallel pair matrix."""
import os, sys, pytest, asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.async_runner import AsyncTestRunner, StrategyItem, TcpTestResult


@pytest.mark.asyncio
async def test_pair_parallel():
    """2 UDP pairs = 2 asyncio tasks."""
    runner = AsyncTestRunner(pool_size=3)
    await runner.start()
    tcp_res = TcpTestResult(
        item=StrategyItem(label="tcp_ok", strategy="fake:blob=stun:repeats=6:tcp_ts=-1000"),
        domain="discord.com", success=True, latency_ms=100
    )
    udp = [StrategyItem(label="u1", strategy="fake:blob=discord_udp:repeats=6"),
           StrategyItem(label="u2", strategy="fake:blob=discord_udp:repeats=12")]
    pairs = await runner.test_pair_matrix([tcp_res], udp, "d", voice_ip="1.2.3.4", voice_port=5)
    assert len(pairs) == 2
    await runner.stop()


@pytest.mark.asyncio
async def test_pair_no_working_tcp():
    """0 pairs when all TCP FAIL."""
    runner = AsyncTestRunner(pool_size=2)
    await runner.start()
    tcp_res = TcpTestResult(
        item=StrategyItem(label="tcp_fail", strategy="fake:repeats=1"),
        domain="d", success=False
    )
    pairs = await runner.test_pair_matrix([tcp_res], [StrategyItem(label="u", strategy="f")],
                                           "d", voice_ip="1.2.3.4", voice_port=5)
    assert len(pairs) == 0
    await runner.stop()


@pytest.mark.asyncio
async def test_pair_udp_bypass():
    """udp_bypass=True forces UDP even on FAIL TCP."""
    runner = AsyncTestRunner(pool_size=2)
    await runner.start()
    tcp_res = TcpTestResult(
        item=StrategyItem(label="tcp_fail", strategy="fake:repeats=1"),
        domain="d", success=False
    )
    pairs = await runner.test_pair_matrix(
        [tcp_res], [StrategyItem(label="u", strategy="f")],
        "d", voice_ip="1.2.3.4", voice_port=5, udp_bypass=True
    )
    assert len(pairs) == 1
    await runner.stop()


@pytest.mark.asyncio
async def test_pair_resume_skip():
    """Resume skips completed pairs based on labels."""
    runner = AsyncTestRunner(pool_size=2)
    await runner.start()
    tcp = TcpTestResult(
        item=StrategyItem(label="tcp_a", strategy="f"), domain="d", success=True
    )
    # resume_from says pair (tcp_a, u_a) was already done
    pairs = await runner.test_pair_matrix(
        [tcp], [StrategyItem(label="u_a", strategy="f")],
        "d", voice_ip="1.2.3.4", voice_port=5,
        resume_from=(0, 0, "", "", "u_a", "tcp_a"),
    )
    # Should skip the pair
    assert len(pairs) == 0, f"Resume should skip completed pairs, got {len(pairs)}"
    await runner.stop()
