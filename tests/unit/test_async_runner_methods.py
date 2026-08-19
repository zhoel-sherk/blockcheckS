"""Unit tests for AsyncTestRunner methods (mock pool + probes, no netns)."""

from __future__ import annotations

import pytest

from blockchecks.engine.generators.base import StrategyItem

pytestmark = pytest.mark.unit


def _item(strategy="fake:blob=stun:repeats=6:tcp_ts=-1000", label="fake"):
    return StrategyItem(label=label, strategy=strategy)


async def test_runner_test_tcp_success(mock_runner):
    r = await mock_runner.test_tcp(_item(), "discord.com", timeout=5.0)
    assert r.success is True
    assert r.http_code == 200


async def test_runner_test_tcp_wssize_retry(mock_runner, monkeypatch):
    """On FAIL with try_wssize, retries with wssize extra."""
    mock_runner.try_wssize = True
    monkeypatch.setattr(
        "blockchecks.engine.async_runner._run_tcp_check",
        lambda *a, **k: {"success": False, "http_code": 0}
        if not any("wssize" in str(x) for x in a)
        else {"success": True, "http_code": 200},
    )
    r = await mock_runner.test_tcp(_item(), "discord.com", timeout=5.0)
    assert r.success is True


async def test_runner_test_tcp_domains(mock_runner, monkeypatch):
    def fake_multi(ns, strategy, domains, timeout, **kw):
        return {d: {"success": True, "http_code": 200, "latency_ms": 5.0} for d in domains}

    monkeypatch.setattr(
        "blockchecks.engine.async_runner._run_tcp_check_multi", fake_multi
    )
    results = await mock_runner.test_tcp_domains(
        _item(), ["discord.com", "discord.gg"], timeout=5.0
    )
    assert len(results) == 2
    assert all(x.success for x in results)


async def test_runner_test_quic(mock_runner, monkeypatch):
    monkeypatch.setattr(
        "blockchecks.engine.async_runner._run_quic_check",
        lambda *a, **k: {"success": True, "http_code": 0, "http_version": "HTTP/3"},
    )
    r = await mock_runner.test_quic(_item(), "discord.com", timeout=5.0)
    assert r.success is True


async def test_runner_test_udp(mock_runner, monkeypatch):
    monkeypatch.setattr(
        "blockchecks.engine.async_runner._run_udp_check",
        lambda *a, **k: {"success": True, "latency_ms": 8.0},
    )
    saved: list[tuple] = []

    async def _save(strategy, domain, *, protocol, latency_ms, http_code):
        saved.append((strategy, domain, protocol, latency_ms))

    monkeypatch.setattr(
        "blockchecks.engine.async_runner._save_pass_strategy_data_block", _save
    )
    r = await mock_runner.test_udp(_item(), "35.217.5.42", 50006, timeout=3.0)
    assert r.success is True
    assert saved == [(_item().strategy, "35.217.5.42:50006", "udp", 8.0)]


async def test_runner_test_udp_fail(mock_runner, monkeypatch):
    monkeypatch.setattr(
        "blockchecks.engine.async_runner._run_udp_check",
        lambda *a, **k: {"success": False, "latency_ms": 0},
    )
    r = await mock_runner.test_udp(_item(), "35.217.5.42", 50006, timeout=3.0)
    assert r.success is False


async def test_runner_batch_tcp_classic(mock_runner):
    mock_runner.lua_bridge = False
    items = [_item(label="a"), _item(label="b")]
    results = await mock_runner.test_batch_tcp(items, "discord.com", timeout=5.0)
    assert len(results) == 2
    assert all(r.success for r in results)
