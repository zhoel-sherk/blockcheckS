"""Unit tests for ProbeResultLogger (mocked DB/data_block)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.probe_result_logger import (
    ProbeResultLogger,
    resolved_ip_for_log,
    tcp_row_status,
)
from blockchecks.engine.results import TcpTestResult, UdpTestResult
from blockchecks.service.batch_service import PROBE_SKIP_ERRORS

pytestmark = pytest.mark.unit


def _item(strategy="fake:blob=stun:repeats=6:tcp_ts=-1000", label="fake"):
    return StrategyItem(label=label, strategy=strategy)


def _tcp_result(**kwargs) -> TcpTestResult:
    defaults = {
        "item": _item(),
        "domain": "discord.com",
        "success": True,
        "http_code": 200,
        "latency_ms": 12.0,
        "content_valid": True,
        "read_rate_bps": 0.0,
        "error": "",
        "used_ip": "",
        "probe_host": "",
    }
    defaults.update(kwargs)
    return TcpTestResult(**defaults)


@pytest.mark.parametrize(
    ("result_kwargs", "expected"),
    [
        ({"success": True}, "PASS"),
        ({"success": False}, "FAIL"),
        ({"success": False, "throttled": True}, "THROTTLED"),
        ({"success": False, "error": next(iter(PROBE_SKIP_ERRORS))}, "SKIPPED"),
    ],
)
def test_tcp_row_status(result_kwargs, expected):
    assert tcp_row_status(_tcp_result(**result_kwargs)) == expected


@pytest.mark.parametrize(
    ("used_ip", "resolved_ip", "expected"),
    [
        ("2.2.2.2", "1.1.1.1", "2.2.2.2"),
        ("", "1.1.1.1", "1.1.1.1"),
        ("", None, ""),
    ],
)
def test_resolved_ip_for_log(used_ip, resolved_ip, expected):
    assert resolved_ip_for_log(used_ip, resolved_ip) == expected


@pytest.mark.asyncio(loop_scope="package")
async def test_log_tcp_probe_prefers_used_ip():
    db = MagicMock()
    db.log_tcp = AsyncMock()
    logger = ProbeResultLogger(db)
    result = _tcp_result(used_ip="2.2.2.2")

    await logger.log_tcp_probe(
        _item(),
        "discord.com",
        result,
        resolved_ip="1.1.1.1",
        dns_verdict="ok",
        doh_server="cloudflare",
    )

    assert db.log_tcp.await_args.kwargs["resolved_ip"] == "2.2.2.2"
    assert db.log_tcp.await_args.kwargs["probe_host"] == ""


@pytest.mark.asyncio(loop_scope="package")
async def test_log_tcp_result_saves_data_block_on_pass():
    db = MagicMock()
    db.log_tcp = AsyncMock()
    logger = ProbeResultLogger(db)
    result = _tcp_result(success=True, used_ip="2.2.2.2", probe_host="cdn.example")

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

    save.assert_awaited_once()
    assert db.log_tcp.await_args.kwargs["resolved_ip"] == "2.2.2.2"
    assert db.log_tcp.await_args.kwargs["probe_host"] == "cdn.example"
    assert db.log_tcp.await_args.kwargs["fail_phase"] == result.fail_phase


@pytest.mark.asyncio(loop_scope="package")
async def test_log_quic_result_writes_quic_proto():
    db = MagicMock()
    db.log_tcp = AsyncMock()
    logger = ProbeResultLogger(db)
    result = _tcp_result(success=False, error="timeout", probe_host="h3.example")

    await logger.log_quic_result(
        _item(),
        "discord.com",
        result,
        resolved_ip="1.2.3.4",
        dns_verdict="",
        doh_server="",
    )

    assert db.log_tcp.await_args.kwargs["proto"] == "quic"
    assert db.log_tcp.await_args.kwargs["resolved_ip"] == "1.2.3.4"


@pytest.mark.asyncio(loop_scope="package")
async def test_log_udp_result_saves_on_success():
    db = MagicMock()
    db.log_udp = AsyncMock()
    logger = ProbeResultLogger(db)
    result = UdpTestResult(item=_item(), target="35.217.5.42:50006", success=True, latency_ms=8.0)

    with patch(
        "blockchecks.engine.probe_result_logger._save_pass_data_block",
        new_callable=AsyncMock,
    ) as save:
        await logger.log_udp_result(_item(), "35.217.5.42:50006", result)

    db.log_udp.assert_awaited_once()
    save.assert_awaited_once_with(
        _item().strategy,
        "35.217.5.42:50006",
        protocol="udp",
        latency_ms=8.0,
        http_code=0,
    )


@pytest.mark.asyncio(loop_scope="package")
async def test_logger_noop_without_db():
    logger = ProbeResultLogger(None)
    result = _tcp_result()
    await logger.log_tcp_probe(
        _item(), "discord.com", result, resolved_ip=None, dns_verdict="", doh_server=""
    )
