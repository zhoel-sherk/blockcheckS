"""Unit tests for bench_settle — settle×curl grid benchmark."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.cli.commands.bench_settle import (
    _load_strategies,
    _parse_floats,
    cmd_bench_settle,
)

pytestmark = pytest.mark.unit


def test_parse_floats_default():
    assert _parse_floats("", (0.1, 0.2)) == (0.1, 0.2)


def test_parse_floats_values():
    assert _parse_floats("0.1,0.5,1.0", ()) == (0.1, 0.5, 1.0)
    assert _parse_floats("0.5,,2.0", ()) == (0.5, 2.0)


def test_load_strategies_preset_missing_with_strategy():
    args = SimpleNamespace(strategy_preset="none", strategy="fake:blob=stun:repeats=6")
    with (
        patch(
            "blockchecks.cli.presets.resolve_strategy_preset",
            side_effect=FileNotFoundError,
        ),
        patch(
            "blockchecks.cli.commands.bench_settle.StrategyLoader.from_string",
            return_value=["fake:blob=stun:repeats=6"],
        ),
    ):
        items = _load_strategies(args)
    assert len(items) == 1


def test_load_strategies_preset_missing_no_strategy():
    args = SimpleNamespace(strategy_preset="none", strategy=None)
    with patch(
        "blockchecks.cli.presets.resolve_strategy_preset",
        side_effect=FileNotFoundError,
    ):
        items = _load_strategies(args)
    assert items == []


def test_load_strategies_ok():
    args = SimpleNamespace(strategy_preset="x")
    with (
        patch(
            "blockchecks.cli.presets.resolve_strategy_preset",
            return_value="/tmp/x.tls",
        ),
        patch(
            "blockchecks.cli.commands.bench_settle.StrategyLoader.from_file",
            return_value=["a", "b"],
        ),
    ):
        items = _load_strategies(args)
    assert len(items) == 2
    assert items[0].label.startswith("bench_")


def _args(**over):
    base = dict(
        domain="youtube.com",
        strategy_preset="timeout-benchmark",
        strategy=None,
        settle_times="",
        curl_timeouts="",
        max_strategies=2,
        no_secure_dns=False,
        no_write_profile=True,
        write_profile=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


def test_cmd_bench_settle_no_strategies():
    args = _args()
    with patch("blockchecks.cli.commands.bench_settle._load_strategies", return_value=[]):
        rc = asyncio.run(cmd_bench_settle(args))
    assert rc == 1


def test_cmd_bench_settle_dns_error():
    args = _args()
    with (
        patch("blockchecks.cli.commands.bench_settle._load_strategies", return_value=[MagicMock()]),
        patch(
            "blockchecks.cli.commands.bench_settle.prepare_dns_for_run",
            return_value=(None, [], 4),
        ),
        patch("blockchecks.data_block.provider.provider_name"),
    ):
        rc = asyncio.run(cmd_bench_settle(args))
    assert rc == 4


def test_cmd_bench_settle_runs_grid(tmp_path):
    args = _args()
    item = MagicMock()
    item.strategy = "fake:a"
    item.is_config = False
    item.label = "bench_0"
    runner = AsyncMock()
    runner.start = AsyncMock()
    runner.stop = AsyncMock()
    pool = AsyncMock()
    pool.acquire = AsyncMock(return_value="ns1")
    pool.release = AsyncMock()
    runner.pool = pool
    runner.python = "python3"
    with (
        patch("blockchecks.cli.commands.bench_settle._load_strategies", return_value=[item]),
        patch(
            "blockchecks.cli.commands.bench_settle.prepare_dns_for_run",
            return_value=(MagicMock(), [], None),
        ),
        patch("blockchecks.data_block.provider.provider_name"),
        patch("blockchecks.cli.commands.bench_settle.AsyncTestRunner", return_value=runner),
        patch(
            "blockchecks.cli.commands.bench_settle._run_tcp_check",
            return_value={"success": True, "settle_ms": 100, "latency_ms": 50, "http_code": 200},
        ),
    ):
        rc = asyncio.run(cmd_bench_settle(args))
    assert rc == 0
    runner.start.assert_awaited_once()
    runner.stop.assert_awaited_once()


def test_cmd_bench_settle_writes_profile(tmp_path):
    args = _args(no_write_profile=False, write_profile=str(tmp_path / "p.json"))
    item = MagicMock()
    item.strategy = "fake:a"
    item.is_config = False
    item.label = "bench_0"
    runner = AsyncMock()
    runner.start = AsyncMock()
    runner.stop = AsyncMock()
    pool = AsyncMock()
    pool.acquire = AsyncMock(return_value="ns1")
    pool.release = AsyncMock()
    runner.pool = pool
    runner.python = "python3"
    profile = MagicMock()
    profile.defaults = None
    with (
        patch("blockchecks.cli.commands.bench_settle._load_strategies", return_value=[item]),
        patch(
            "blockchecks.cli.commands.bench_settle.prepare_dns_for_run",
            return_value=(MagicMock(), [], None),
        ),
        patch("blockchecks.data_block.provider.provider_name"),
        patch("blockchecks.cli.commands.bench_settle.AsyncTestRunner", return_value=runner),
        patch(
            "blockchecks.cli.commands.bench_settle._run_tcp_check",
            return_value={"success": False, "settle_ms": 0, "latency_ms": 0, "http_code": 0},
        ),
        patch(
            "blockchecks.cli.commands.bench_settle.build_profile_from_rows",
            return_value=profile,
        ),
        patch(
            "blockchecks.cli.commands.bench_settle.save_profile",
            return_value=str(tmp_path / "p.json"),
        ),
    ):
        rc = asyncio.run(cmd_bench_settle(args))
    assert rc == 0
