"""S2b: fan-out / async_runner must not write harvest PASS without APPLIED."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.engine.async_runner import CampaignProbeResultLogger, campaign_harvest_status
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.results import TcpTestResult

pytestmark = pytest.mark.unit


def _item() -> StrategyItem:
    return StrategyItem(label="fake", strategy="fake:blob=stun:repeats=6:tcp_ts=-1000")


def _result(**kwargs) -> TcpTestResult:
    defaults = {
        "item": _item(),
        "domain": "discord.com",
        "success": True,
        "http_code": 200,
        "latency_ms": 12.0,
    }
    defaults.update(kwargs)
    return TcpTestResult(**defaults)


@pytest.mark.parametrize(
    ("backend", "bridge_applied", "expected"),
    [
        ("lua_bridge", True, "PASS"),
        ("lua_bridge", False, "FAIL"),
        ("lua_bridge", None, "FAIL"),
        ("oneshot", None, "FAIL"),
        ("oneshot", True, "FAIL"),
    ],
)
def test_campaign_harvest_status(backend, bridge_applied, expected):
    assert campaign_harvest_status(_result(bridge_applied=bridge_applied), backend) == expected


@pytest.mark.asyncio(loop_scope="package")
async def test_fanout_oneshot_logs_fail_not_pass(mock_runner, monkeypatch):
    """HTTP 200 fan-out rows are stored FAIL + fail_phase=oneshot (not harvest PASS)."""

    def fake_multi(ns, strategy, domains, timeout, **kw):
        return {d: {"success": True, "http_code": 200, "latency_ms": 5.0} for d in domains}

    monkeypatch.setattr("blockchecks.engine.async_runner._run_tcp_check_multi", fake_multi)
    statuses: list[str] = []
    phases: list[str] = []

    async def capture_log(*args, **kwargs):
        statuses.append(args[2])
        phases.append(kwargs.get("fail_phase") or "")

    monkeypatch.setattr(mock_runner.db, "log_tcp", capture_log)
    await mock_runner.test_tcp_domains(_item(), ["a.com", "b.com"], timeout=5.0)
    assert statuses == ["FAIL", "FAIL"]
    assert phases == ["oneshot", "oneshot"]


@pytest.mark.asyncio(loop_scope="package")
async def test_lua_bridge_logs_fail_without_applied():
    db = MagicMock()
    db.log_tcp = AsyncMock()
    logger = CampaignProbeResultLogger(db)
    result = _result(bridge_applied=False)

    await logger.log_tcp_result(
        _item(),
        "discord.com",
        result,
        resolved_ip="1.1.1.1",
        dns_verdict="ok",
        doh_server="cloudflare",
    )

    assert db.log_tcp.await_args.args[2] == "FAIL"
    assert db.log_tcp.await_args.kwargs["fail_phase"] == "no_bridge_applied"
    assert db.log_tcp.await_args.kwargs["bridge_applied"] is False


@pytest.mark.asyncio(loop_scope="package")
async def test_lua_bridge_logs_pass_with_applied():
    db = MagicMock()
    db.log_tcp = AsyncMock()
    logger = CampaignProbeResultLogger(db)
    result = _result(bridge_applied=True)

    with patch(
        "blockchecks.engine.probe_result_logger._save_pass_data_block",
        new_callable=AsyncMock,
    ) as save:
        await logger.log_tcp_result(
            _item(),
            "discord.com",
            result,
            resolved_ip="1.1.1.1",
            dns_verdict="ok",
            doh_server="cloudflare",
        )

    assert db.log_tcp.await_args.args[2] == "PASS"
    save.assert_awaited_once()
