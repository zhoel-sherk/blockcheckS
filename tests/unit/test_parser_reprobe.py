"""Parser tests for --reprobe-failed."""

from __future__ import annotations

import pytest

from blockchecks.cli.parser import build_parser

pytestmark = pytest.mark.unit


def test_reprobe_failed_defaults_to_zero():
    ns = build_parser().parse_args(["pair", "-d", "youtube.com", "--resume"])
    assert ns.reprobe_failed == 0


def test_reprobe_failed_accepts_int():
    ns = build_parser().parse_args(
        ["pair", "-d", "youtube.com", "--resume", "--reprobe-failed", "3"]
    )
    assert ns.reprobe_failed == 3
