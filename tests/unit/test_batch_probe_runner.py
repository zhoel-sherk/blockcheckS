"""AsyncTestRunner delegation to ProbeBatchService."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.engine.async_runner import AsyncTestRunner, TcpTestResult
from blockchecks.engine.generators.base import StrategyItem


@pytest.mark.unit
@pytest.mark.asyncio(loop_scope="package")
async def test_test_batch_tcp_delegates_bridge() -> None:
    runner = AsyncTestRunner(pool_size=2, lua_bridge=True, bridge_batch=10)
    items = [StrategyItem("a", "fake:a"), StrategyItem("b", "fake:b")]
    mock_results = [
        TcpTestResult(item=items[0], domain="discord.com", success=True, latency_ms=50),
        TcpTestResult(item=items[1], domain="discord.com", success=False, latency_ms=0),
    ]

    with patch.object(
        runner,
        "_run_probe_batch",
        new=AsyncMock(return_value=mock_results),
    ) as mock_batch:
        out = await runner.test_batch_tcp(items, "discord.com", timeout=3.0)
        mock_batch.assert_called_once()
        assert mock_batch.call_args[0][3] == "lua_bridge"
        assert len(out) == 2


@pytest.mark.unit
@pytest.mark.asyncio(loop_scope="package")
async def test_run_probe_batch_uses_semaphore() -> None:
    runner = AsyncTestRunner(pool_size=1)
    acquire = AsyncMock(return_value="bs-p-0")
    release = AsyncMock()
    runner.pool.acquire = acquire
    runner.pool.release = release
    items = [StrategyItem("x", "fake:x")]

    with patch(
        "blockchecks.engine.services.batch_probe.run_tcp_check_bridge",
        return_value={"success": True, "http_code": 200, "latency_ms": 1},
    ):
        inst = MagicMock()
        inst.boot.return_value = 0.05
        with patch("blockchecks.engine.services.batch_probe.BridgeSession", return_value=inst):
            await runner._run_probe_batch(items, "discord.com", 5.0, "lua_bridge")

    acquire.assert_called_once()
    release.assert_called_once_with("bs-p-0")
