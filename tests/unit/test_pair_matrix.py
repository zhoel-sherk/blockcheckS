"""Pair matrix unit tests with mocked probes."""

from __future__ import annotations

import pytest

from blockchecks.engine.async_runner import StrategyItem, TcpTestResult
from blockchecks.engine.store import Checkpoint

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_pair_parallel(mock_runner):
    tcp_res = TcpTestResult(
        item=StrategyItem(label="tcp_ok", strategy="fake:repeats=1"),
        domain="discord.com",
        success=True,
        latency_ms=100,
    )
    udp = [
        StrategyItem(label="u1", strategy="fake:repeats=6"),
        StrategyItem(label="u2", strategy="fake:repeats=12"),
    ]
    pairs = await mock_runner.test_pair_matrix(
        [tcp_res],
        udp,
        "d",
        voice_ip="1.2.3.4",
        voice_port=5,
    )
    assert len(pairs) == 2
    assert all(p.overall == "PASS" for p in pairs)
    assert all(p.tcp_ok and p.udp_ok for p in pairs)
    assert {p.udp_item.label for p in pairs} == {"u1", "u2"}


@pytest.mark.asyncio
async def test_pair_partial_when_udp_fails(mock_runner, monkeypatch):
    def fail_udp(*a, **k):
        return {"success": False, "latency_ms": 0.0, "detail": "timeout"}

    monkeypatch.setattr("blockchecks.engine.async_runner._run_udp_check", fail_udp)
    tcp_res = TcpTestResult(
        item=StrategyItem(label="tcp_ok", strategy="fake:repeats=1"),
        domain="d",
        success=True,
        latency_ms=50,
    )
    pairs = await mock_runner.test_pair_matrix(
        [tcp_res],
        [StrategyItem(label="u", strategy="f")],
        "d",
        voice_ip="1.2.3.4",
        voice_port=5,
    )
    assert len(pairs) == 1
    assert pairs[0].overall == "PARTIAL"
    assert pairs[0].tcp_ok is True
    assert pairs[0].udp_ok is False


@pytest.mark.asyncio
async def test_pair_fail_when_tcp_and_udp_fail(mock_runner, monkeypatch):
    def fail_udp(*a, **k):
        return {"success": False, "latency_ms": 0.0, "detail": "stun fail"}

    monkeypatch.setattr("blockchecks.engine.async_runner._run_udp_check", fail_udp)
    tcp_res = TcpTestResult(
        item=StrategyItem(label="tcp_fail", strategy="fake:repeats=1"),
        domain="d",
        success=False,
    )
    pairs = await mock_runner.test_pair_matrix(
        [tcp_res],
        [StrategyItem(label="u", strategy="f")],
        "d",
        voice_ip="1.2.3.4",
        voice_port=5,
        udp_bypass=True,
    )
    assert len(pairs) == 1
    assert pairs[0].overall == "FAIL"
    assert pairs[0].tcp_ok is False
    assert pairs[0].udp_ok is False


@pytest.mark.asyncio
async def test_pair_no_working_tcp(mock_runner):
    tcp_res = TcpTestResult(
        item=StrategyItem(label="tcp_fail", strategy="fake:repeats=1"),
        domain="d",
        success=False,
    )
    pairs = await mock_runner.test_pair_matrix(
        [tcp_res],
        [StrategyItem(label="u", strategy="f")],
        "d",
        voice_ip="1.2.3.4",
        voice_port=5,
    )
    assert len(pairs) == 0


@pytest.mark.asyncio
async def test_pair_udp_bypass(mock_runner):
    tcp_res = TcpTestResult(
        item=StrategyItem(label="tcp_fail", strategy="fake:repeats=1"),
        domain="d",
        success=False,
    )
    pairs = await mock_runner.test_pair_matrix(
        [tcp_res],
        [StrategyItem(label="u", strategy="f")],
        "d",
        voice_ip="1.2.3.4",
        voice_port=5,
        udp_bypass=True,
    )
    assert len(pairs) == 1


@pytest.mark.asyncio
async def test_pair_resume_completed_set(mock_runner, temp_db):
    """Pairs already in DB are skipped; checkpoint idx alone must not skip others."""
    await temp_db.log_pair("tcp_a", "u_a", "d", True, False, True, 10, 0, 8, "PASS")
    tcp_a = TcpTestResult(
        item=StrategyItem(label="tcp_a", strategy="f"),
        domain="d",
        success=True,
    )
    tcp_b = TcpTestResult(
        item=StrategyItem(label="tcp_b", strategy="f"),
        domain="d",
        success=True,
    )
    # Misleading high idx (as if parallel wrote checkpoint for tcp_b first)
    cp = Checkpoint(
        tcp_idx=1,
        udp_idx=0,
        timestamp="",
        note="",
        fingerprint="",
        tcp_label="tcp_b",
        udp_label="u_a",
    )
    pairs = await mock_runner.test_pair_matrix(
        [tcp_a, tcp_b],
        [StrategyItem(label="u_a", strategy="f")],
        "d",
        voice_ip="1.2.3.4",
        voice_port=5,
        resume_from=cp,
    )
    # tcp_a+u_a skipped (in DB); tcp_b+u_a still runs despite checkpoint idx
    assert len(pairs) == 1
    assert pairs[0].tcp_item.label == "tcp_b"


@pytest.mark.asyncio
async def test_pair_checkpoint_idx_does_not_skip(mock_runner):
    """Without completed-set entries, checkpoint idx must not block any pair."""
    tcp = TcpTestResult(
        item=StrategyItem(label="tcp_a", strategy="f"),
        domain="d",
        success=True,
    )
    cp = Checkpoint(
        tcp_idx=0,
        udp_idx=0,
        timestamp="",
        note="",
        fingerprint="",
        tcp_label="tcp_a",
        udp_label="u_a",
    )
    pairs = await mock_runner.test_pair_matrix(
        [tcp],
        [StrategyItem(label="u_a", strategy="f")],
        "d",
        voice_ip="1.2.3.4",
        voice_port=5,
        resume_from=cp,
    )
    assert len(pairs) == 1


@pytest.mark.asyncio
async def test_pair_throttled_overall(mock_runner):
    tcp = TcpTestResult(
        item=StrategyItem(label="tcp_t", strategy="f"),
        domain="d",
        success=True,
        throttled=True,
        latency_ms=200,
    )
    pairs = await mock_runner.test_pair_matrix(
        [tcp],
        [StrategyItem(label="u", strategy="f")],
        "d",
        voice_ip="1.2.3.4",
        voice_port=5,
    )
    assert len(pairs) == 1
    assert pairs[0].overall == "THROTTLED"
