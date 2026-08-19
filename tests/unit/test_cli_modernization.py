"""Tests for modernized CLI flags: inverse flags, preflight options, profiles."""

from __future__ import annotations

import argparse
from types import SimpleNamespace

from blockchecks.cli.parser import add_adaptive_args, add_profile_args
from blockchecks.cli.profiles import PROFILES, apply_profile
from blockchecks.engine.preflight import PreflightOptions


def test_preflight_options_no_preflight():
    args = SimpleNamespace(no_preflight=True, timeout=5.0)
    opts = PreflightOptions.from_args(args)
    assert opts.skip_baseline is True
    assert opts.skip_port_block is True
    assert opts.skip_prolog is True
    assert opts.skip_ip_block is True
    assert opts.skip_nfqws2_check is True
    assert opts.skip_dns_audit is True


def test_preflight_options_quick():
    args = SimpleNamespace(quick=True, timeout=5.0)
    opts = PreflightOptions.from_args(args)
    assert opts.skip_baseline is True
    assert opts.skip_port_block is True
    assert opts.skip_ip_block is True
    assert opts.skip_prolog is False  # prolog still runs in quick mode


def test_adaptive_args_parser():
    p = argparse.ArgumentParser()
    add_adaptive_args(p)
    parsed_default = p.parse_args([])
    assert parsed_default.no_adaptive is False

    parsed_no_adaptive = p.parse_args(["--no-adaptive"])
    assert parsed_no_adaptive.no_adaptive is True

    parsed_adaptive = p.parse_args(["--adaptive"])
    assert parsed_adaptive.no_adaptive is False


def test_profile_application():
    for name, expected in PROFILES.items():
        args = SimpleNamespace(profile=name)
        apply_profile(args)
        for k, v in expected.items():
            assert getattr(args, k) == v


def test_profile_args_parser():
    p = argparse.ArgumentParser()
    add_profile_args(p)
    parsed = p.parse_args(["--profile", "20h"])
    assert parsed.profile == "20h"
