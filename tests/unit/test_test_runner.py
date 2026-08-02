"""Unit tests for sync TestRunner deadline."""

import asyncio
from unittest.mock import MagicMock, patch

from blockchecks.engine.run_deadline import RunDeadline
from blockchecks.engine.test_runner import TestRunner as SyncTestRunner


def test_sequential_stops_on_deadline():
    deadline = RunDeadline(asyncio.Event(), budget_sec=0.0)
    deadline.arm()

    runner = SyncTestRunner()
    strategies = ["fake:a", "fake:b", "fake:c"]

    with patch.object(runner, "test_single") as mock_single:
        mock_single.return_value = MagicMock(
            success=False, latency_ms=0, http_status=0, error=None, strategy="fake:a"
        )
        report = runner.test_sequential(strategies, "example.com", deadline=deadline)

    assert report.stopped_reason == "time_limit"
    assert len(report.results) == 0
    mock_single.assert_not_called()
