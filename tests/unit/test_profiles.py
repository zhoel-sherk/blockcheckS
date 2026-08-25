"""Tests for CLI --profile bundles (apply_profile does not clobber explicit args)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from blockchecks.cli.profiles import PROFILES, apply_profile, flags_present_in_argv

pytestmark = pytest.mark.unit


def test_profile_application_sets_missing_defaults():
    for name, expected in PROFILES.items():
        args = SimpleNamespace(profile=name)
        apply_profile(args)
        for k, v in expected.items():
            assert getattr(args, k) == v


def test_profile_keeps_non_default_max():
    args = SimpleNamespace(profile="smoke", max=50)
    apply_profile(args)
    assert args.max == 50
    assert args.scan_level == "fast"
    assert args.quick is True


def test_profile_respects_explicit_cli_set():
    args = SimpleNamespace(
        profile="smoke",
        max=100,
        timeout=3.0,
        _explicit_cli={"max", "timeout"},
    )
    apply_profile(args)
    assert args.max == 100
    assert args.timeout == 3.0
    assert args.quick is True


def test_flags_present_in_argv_detects_timeout_and_max():
    found = flags_present_in_argv(["scan", "--profile", "smoke", "--max", "50", "--timeout=9"])
    assert found == {"max", "timeout"}


def test_unknown_profile_is_noop():
    args = SimpleNamespace(profile="nope", max=7)
    apply_profile(args)
    assert args.max == 7


def test_no_profile_is_noop():
    args = SimpleNamespace(max=7)
    apply_profile(args)
    assert args.max == 7


def test_profile_keeps_explicit_max_zero():
    args = SimpleNamespace(profile="smoke", max=0, _explicit_cli={"max"})
    apply_profile(args)
    assert args.max == 0
    assert args.scan_level == "fast"
    assert args.quick is True


def test_profile_max_zero_without_explicit_cli_is_unset_for_scan_default():
    """Scan/pair default max=100 is still treated as unset; smoke caps to 20."""
    args = SimpleNamespace(profile="smoke", max=100)
    apply_profile(args)
    assert args.max == 20
