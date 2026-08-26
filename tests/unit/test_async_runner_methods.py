"""Unit tests for AsyncTestRunner methods (mock pool + probes, no netns)."""

from __future__ import annotations

import logging

import pytest

from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.probe_executors import TcpProbeExecutor
from blockchecks.engine.probe_result_logger import ProbeResultLogger
from blockchecks.engine.settle_profile import SettleProfile, TimingOverride

pytestmark = pytest.mark.unit


def _item(strategy="fake:blob=stun:repeats=6:tcp_ts=-1000", label="fake"):
    return StrategyItem(label=label, strategy=strategy)


async def test_runner_test_tcp_success(mock_runner):
    r = await mock_runner.test_tcp(_item(), "discord.com", timeout=5.0)
    assert r.success is True
    assert r.http_code == 200


async def test_runner_test_tcp_logs_used_ip(mock_runner, monkeypatch):
    """ST-3: DB row uses result.used_ip when retry-on-next-IP succeeds."""
    logged: list[str] = []
    original_log = mock_runner.db.log_tcp

    async def capture_log(*args, **kwargs):
        logged.append(kwargs.get("resolved_ip") or "")
        return await original_log(*args, **kwargs)

    monkeypatch.setattr(mock_runner.db, "log_tcp", capture_log)
    monkeypatch.setattr(
        "blockchecks.engine.async_runner._run_tcp_check",
        lambda *a, **k: {
            "success": True,
            "http_code": 200,
            "latency_ms": 10.0,
            "content_len": 100,
            "content_ok": True,
            "used_ip": "2.2.2.2",
        },
    )
    r = await mock_runner.test_tcp(_item(), "discord.com", timeout=5.0)
    assert r.used_ip == "2.2.2.2"
    assert logged == ["2.2.2.2"]


async def test_runner_test_tcp_wssize_retry(mock_runner, monkeypatch):
    """On FAIL with try_wssize, retries with wssize extra and capped timeout."""
    mock_runner.try_wssize = True
    timeouts: list[float] = []

    def fake_tcp(*a, **k):
        if len(a) > 3:
            timeouts.append(a[3])
        if not any("wssize" in str(x) for x in a):
            return {"success": False, "http_code": 0}
        return {"success": True, "http_code": 200}

    monkeypatch.setattr("blockchecks.engine.async_runner._run_tcp_check", fake_tcp)
    r = await mock_runner.test_tcp(_item(), "discord.com", timeout=5.0)
    assert r.success is True
    assert timeouts == [5.0, 1.5]


async def test_runner_test_tcp_domains(mock_runner, monkeypatch):
    def fake_multi(ns, strategy, domains, timeout, **kw):
        return {d: {"success": True, "http_code": 200, "latency_ms": 5.0} for d in domains}

    monkeypatch.setattr("blockchecks.engine.async_runner._run_tcp_check_multi", fake_multi)
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

    monkeypatch.setattr("blockchecks.engine.async_runner._save_pass_strategy_data_block", _save)
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


def _timing_runner(profile: SettleProfile) -> TcpProbeExecutor:
    host = type(
        "_TimingHost",
        (),
        {
            "settle_profile": profile,
            "_timing_override_logged": set(),
            "secure_dns": False,
            "dns_cache": None,
            "dns_audit": {},
            "python": "",
            "disable_ech": False,
            "repeats": 1,
            "parallel_repeats": False,
            "repeats_mode": "fast",
            "quick_break": False,
            "try_wssize": False,
        },
    )()
    return TcpProbeExecutor(host, None, None, ProbeResultLogger(None))


def test_timing_for_explicit_override(caplog):
    profile = SettleProfile(
        defaults=TimingOverride(0.5, 3.0),
        strategies={"fake:blob=stun": TimingOverride(0.2, 1.5)},
        source_path="/tmp/profile.json",
    )
    runner = _timing_runner(profile)
    item = StrategyItem(label="x", strategy="fake:blob=stun")
    with caplog.at_level(logging.INFO):
        timeout, settle_max = runner.timing_for(item, 10.0)
    assert timeout == 1.5
    assert settle_max == 0.2
    assert "settle profile override" in caplog.text
    assert "/tmp/profile.json" in caplog.text

    caplog.clear()
    with caplog.at_level(logging.INFO):
        runner.timing_for(item, 10.0)
    assert "settle profile override" not in caplog.text


def test_timing_for_defaults_fallback(caplog):
    profile = SettleProfile(
        defaults=TimingOverride(0.5, 3.0),
        strategies={"fake:blob=stun": TimingOverride(0.2, 1.5)},
        source_path="/tmp/profile.json",
    )
    runner = _timing_runner(profile)
    item = StrategyItem(label="x", strategy="unknown:strategy")
    with caplog.at_level(logging.WARNING):
        timeout, settle_max = runner.timing_for(item, 10.0)
    assert timeout == 3.0
    assert settle_max == 0.5
    assert "defaults fallback" in caplog.text
    assert "cli_timeout=10.0" in caplog.text


def test_timing_for_preserves_zero_curl_timeout():
    profile = SettleProfile(
        defaults=TimingOverride(0.1, 0.0),
        strategies={"fake:blob=stun": TimingOverride(0.1, 0.0)},
        source_path="/tmp/profile.json",
    )
    runner = _timing_runner(profile)
    item = StrategyItem(label="x", strategy="fake:blob=stun")
    timeout, settle_max = runner.timing_for(item, 10.0)
    assert timeout == 0.0
    assert settle_max == 0.1
