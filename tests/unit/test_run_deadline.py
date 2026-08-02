"""Unit tests for run_deadline."""

import argparse
import asyncio

import pytest

from blockchecks.engine.run_deadline import (
    RunDeadline,
    add_time_limit_args,
    parse_time_limit_seconds,
    validate_time_limit_args,
)


def test_parse_time_limit_hours():
    args = argparse.Namespace(max_timeh=2.0, max_timem=None)
    assert parse_time_limit_seconds(args) == 7200.0


def test_parse_time_limit_minutes():
    args = argparse.Namespace(max_timeh=None, max_timem=90.0)
    assert parse_time_limit_seconds(args) == 5400.0


def test_parse_time_limit_none():
    args = argparse.Namespace(max_timeh=None, max_timem=None)
    assert parse_time_limit_seconds(args) is None


def test_parse_time_limit_mutual_exclusion():
    args = argparse.Namespace(max_timeh=1.0, max_timem=30.0)
    with pytest.raises(ValueError, match="only one"):
        parse_time_limit_seconds(args)


def test_validate_time_limit_args_errors():
    p = argparse.ArgumentParser()
    add_time_limit_args(p)
    args = p.parse_args(["--max-timeh", "1", "--max-timem", "30"])
    with pytest.raises(SystemExit):
        validate_time_limit_args(p, args)


@pytest.mark.asyncio
async def test_deadline_triggers_stop_event():
    stop = asyncio.Event()
    deadline = RunDeadline(stop, budget_sec=0.05)
    deadline.arm()
    await deadline.start_background()
    await asyncio.sleep(0.08)
    assert stop.is_set()
    assert deadline.triggered
    assert deadline.reason == "time_limit"
    await deadline.cancel()


def test_expired_sync():
    stop = asyncio.Event()
    deadline = RunDeadline(stop, budget_sec=0.001)
    deadline.arm()
    import time

    time.sleep(0.01)
    assert deadline.expired_sync()
