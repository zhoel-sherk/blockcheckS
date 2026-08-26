"""Synthetic CQ016 samples — not imported; parsed by test_code_quality only."""

import asyncio


def exception_swallow() -> None:
    try:
        pass
    except Exception:
        pass


def cancelled_swallow() -> None:
    try:
        pass
    except asyncio.CancelledError:
        ...


def exception_logged_ok() -> None:
    import logging

    log = logging.getLogger(__name__)
    try:
        pass
    except Exception:
        log.warning("expected failure")


def exception_noqa() -> None:
    try:
        pass
    except Exception:  # noqa: CQ016
        pass
