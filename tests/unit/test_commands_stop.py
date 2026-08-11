"""Unit tests for the graceful-stop CLI command."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from blockchecks.cli.commands.stop import cmd_stop

pytestmark = pytest.mark.unit


def _stop_args(**over):
    base = dict(force=False, wait=120.0)
    base.update(over)
    return SimpleNamespace(**base)


def test_stop_no_active_run():
    args = _stop_args()
    with patch("blockchecks.cli.commands.stop.request_graceful_stop") as stop:
        stop.return_value = (2, "No active blockcheckS run (missing or stale run.lock)")
        rc = cmd_stop(args)
    assert rc == 2
    stop.assert_called_once_with(force=False, wait_sec=120.0)


def test_stop_graceful_success():
    args = _stop_args()
    with patch("blockchecks.cli.commands.stop.request_graceful_stop") as stop:
        stop.return_value = (0, "Stopped pid 1234 (scan) — DB flush/export completed")
        rc = cmd_stop(args)
    assert rc == 0


def test_stop_force_flag_propagated():
    args = _stop_args(force=True, wait=30.0)
    with patch("blockchecks.cli.commands.stop.request_graceful_stop") as stop:
        stop.return_value = (0, "Force-killed pid 1234")
        rc = cmd_stop(args)
    assert rc == 0
    stop.assert_called_once_with(force=True, wait_sec=30.0)


def test_stop_timeout_returns_1():
    args = _stop_args()
    with patch("blockchecks.cli.commands.stop.request_graceful_stop") as stop:
        stop.return_value = (1, "Timed out after 120s waiting for pid 1234")
        rc = cmd_stop(args)
    assert rc == 1
