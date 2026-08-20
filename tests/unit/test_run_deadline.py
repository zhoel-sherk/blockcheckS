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


# from_args / arm / labels / expired


def test_from_args_returns_none_without_budget():
    stop = asyncio.Event()
    args = argparse.Namespace(max_timeh=None, max_timem=None)
    assert RunDeadline.from_args(stop, args) is None


def test_from_args_creates_deadline():
    stop = asyncio.Event()
    args = argparse.Namespace(max_timeh=None, max_timem=5.0)
    d = RunDeadline.from_args(stop, args)
    assert d is not None
    assert d.budget_sec == 300.0


def test_from_args_mutual_exclusion_raises_system_exit():
    stop = asyncio.Event()
    args = argparse.Namespace(max_timeh=1.0, max_timem=1.0)
    with pytest.raises(SystemExit):
        RunDeadline.from_args(stop, args)


def test_arm_requires_budget():
    stop = asyncio.Event()
    d = RunDeadline(stop, budget_sec=None)
    d.arm()
    assert d._deadline is None


def test_budget_label():
    stop = asyncio.Event()
    assert RunDeadline(stop, budget_sec=7200).budget_label() == "2h"
    assert RunDeadline(stop, budget_sec=60).budget_label() == "1m"
    assert RunDeadline(stop, budget_sec=None).budget_label() == ""


def test_expired_before_deadline():
    stop = asyncio.Event()
    d = RunDeadline(stop, budget_sec=10.0)
    d.arm()
    assert d.expired() is False


def test_expired_after_deadline_sync_sets_event():
    stop = asyncio.Event()
    d = RunDeadline(stop, budget_sec=0.001)
    d.arm()
    import time

    time.sleep(0.01)
    assert d.expired() is True
    assert stop.is_set()
    assert d.reason == "time_limit"


def test_remaining_sec():
    stop = asyncio.Event()
    d = RunDeadline(stop, budget_sec=10.0)
    d.arm()
    assert d.remaining_sec() is not None
    assert d.remaining_sec() >= 0
    assert RunDeadline(stop, budget_sec=None).remaining_sec() is None


def test_expired_sync_no_budget():
    stop = asyncio.Event()
    assert RunDeadline(stop, budget_sec=None).expired_sync() is False


def test_cancel_without_task():
    stop = asyncio.Event()

    async def _go():
        d = RunDeadline(stop, budget_sec=1.0)
        d.arm()
        await d.cancel()  # no background task → no-op

    asyncio.run(_go())


def test_add_time_limit_args_include_export():
    p = argparse.ArgumentParser()
    add_time_limit_args(p, include_export=True)
    ns = p.parse_args(["--max-timem", "10"])
    assert ns.max_timem == 10.0
