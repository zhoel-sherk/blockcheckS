"""Pair matrix unit tests with mocked probes."""
from __future__ import annotations

import pytest

from engine.async_runner import StrategyItem, TcpTestResult
from engine.db_logger import Checkpoint


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_pair_parallel(mock_runner):
    tcp_res = TcpTestResult(
        item=StrategyItem(label="tcp_ok", strategy="fake:repeats=1"),
        domain="discord.com", success=True, latency_ms=100,
    )
    udp = [
        StrategyItem(label="u1", strategy="fake:repeats=6"),
        StrategyItem(label="u2", strategy="fake:repeats=12"),
    ]
    pairs = await mock_runner.test_pair_matrix(
        [tcp_res], udp, "d", voice_ip="1.2.3.4", voice_port=5,
    )
    assert len(pairs) == 2


@pytest.mark.asyncio
async def test_pair_no_working_tcp(mock_runner):
    tcp_res = TcpTestResult(
        item=StrategyItem(label="tcp_fail", strategy="fake:repeats=1"),
        domain="d", success=False,
    )
    pairs = await mock_runner.test_pair_matrix(
        [tcp_res], [StrategyItem(label="u", strategy="f")],
        "d", voice_ip="1.2.3.4", voice_port=5,
    )
    assert len(pairs) == 0


@pytest.mark.asyncio
async def test_pair_udp_bypass(mock_runner):
    tcp_res = TcpTestResult(
        item=StrategyItem(label="tcp_fail", strategy="fake:repeats=1"),
        domain="d", success=False,
    )
    pairs = await mock_runner.test_pair_matrix(
        [tcp_res], [StrategyItem(label="u", strategy="f")],
        "d", voice_ip="1.2.3.4", voice_port=5, udp_bypass=True,
    )
    assert len(pairs) == 1


@pytest.mark.asyncio
async def test_pair_resume_skip(mock_runner):
    tcp = TcpTestResult(
        item=StrategyItem(label="tcp_a", strategy="f"),
        domain="d", success=True,
    )
    cp = Checkpoint(
        tcp_idx=0, udp_idx=0, timestamp="", note="",
        fingerprint="", tcp_label="tcp_a", udp_label="u_a",
    )
    pairs = await mock_runner.test_pair_matrix(
        [tcp], [StrategyItem(label="u_a", strategy="f")],
        "d", voice_ip="1.2.3.4", voice_port=5, resume_from=cp,
    )
    assert len(pairs) == 0
