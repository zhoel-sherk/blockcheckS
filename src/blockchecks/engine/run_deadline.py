"""Wall-clock deadline for full / scan / tcp runs."""

from __future__ import annotations

import argparse
import asyncio
import time
from dataclasses import dataclass, field
from typing import Literal

StopReason = Literal["time_limit", "signal", None]


def parse_time_limit_seconds(args) -> float | None:
    """Return budget in seconds from --max-timeh / --max-timem (mutually exclusive)."""
    hours = getattr(args, "max_timeh", None)
    minutes = getattr(args, "max_timem", None)
    if hours is not None and minutes is not None:
        raise ValueError("use only one of --max-timeh or --max-timem")
    if hours is not None:
        if hours <= 0:
            raise ValueError("--max-timeh must be positive")
        return float(hours) * 3600.0
    if minutes is not None:
        if minutes <= 0:
            raise ValueError("--max-timem must be positive")
        return float(minutes) * 60.0
    return None


def add_time_limit_args(parser: argparse.ArgumentParser, *, include_export: bool = False) -> None:
    """Register --max-timeh / --max-timem on a subparser."""
    g = parser.add_argument_group("time limit")
    g.add_argument(
        "--max-timeh",
        type=float,
        default=None,
        metavar="H",
        help="Stop after H hours (graceful: flush DB, export if applicable)",
    )
    g.add_argument(
        "--max-timem",
        type=float,
        default=None,
        metavar="M",
        help="Stop after M minutes (graceful: flush DB, export if applicable)",
    )
    if include_export:
        g.add_argument(
            "--no-export-on-stop",
            action="store_true",
            help="Skip nfconf export when stopped early (SIGINT or time limit)",
        )


def validate_time_limit_args(parser: argparse.ArgumentParser, args) -> None:
    """Exit with parser error if both time flags are set."""
    if (
        getattr(args, "max_timeh", None) is not None
        and getattr(args, "max_timem", None) is not None
    ):
        parser.error("use only one of --max-timeh or --max-timem")


@dataclass
class RunDeadline:
    """Monotonic deadline that sets *stop_event* when budget expires."""

    stop_event: asyncio.Event
    budget_sec: float | None = None
    triggered: bool = field(default=False, init=False)
    reason: StopReason = field(default=None, init=False)
    _deadline: float | None = field(default=None, init=False)
    _task: asyncio.Task | None = field(default=None, init=False)

    @classmethod
    def from_args(cls, stop_event: asyncio.Event, args) -> RunDeadline | None:
        try:
            sec = parse_time_limit_seconds(args)
        except ValueError as e:
            raise SystemExit(f"ERROR: {e}") from e
        if sec is None:
            return None
        return cls(stop_event=stop_event, budget_sec=sec)

    def arm(self) -> None:
        if self.budget_sec is None:
            return
        self._deadline = time.monotonic() + self.budget_sec

    async def start_background(self) -> None:
        if self._deadline is None:
            return
        self._task = asyncio.create_task(self._wait())

    async def cancel(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _wait(self) -> None:
        if self._deadline is None:
            return
        delay = max(0.0, self._deadline - time.monotonic())
        await asyncio.sleep(delay)
        if not self.stop_event.is_set():
            self.triggered = True
            self.reason = "time_limit"
            self.stop_event.set()
            # Visible in campaign/smoke logs; loops poll stop_event after each job
            print(
                f"  [deadline] fired after {self.budget_label()} — stop_event set (graceful stop)",
                flush=True,
            )

    def expired(self) -> bool:
        if self._deadline is not None and time.monotonic() >= self._deadline:
            if not self.triggered:
                self.triggered = True
                self.reason = "time_limit"
                self.stop_event.set()
            return True
        return self.stop_event.is_set()

    def remaining_sec(self) -> float | None:
        if self._deadline is None:
            return None
        return max(0.0, self._deadline - time.monotonic())

    def expired_sync(self) -> bool:
        """Sync expiry check for bs tcp (no asyncio timer)."""
        if self._deadline is None:
            return False
        return time.monotonic() >= self._deadline

    def budget_label(self) -> str:
        if self.budget_sec is None:
            return ""
        if self.budget_sec >= 3600:
            return f"{self.budget_sec / 3600:.2g}h"
        return f"{self.budget_sec / 60:.0f}m"
