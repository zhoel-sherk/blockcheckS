"""Tests for modernized CLI flags: inverse flags, preflight options, profiles."""

from __future__ import annotations

import argparse
from types import SimpleNamespace

from blockchecks.cli.parser import add_adaptive_args, add_profile_args, namespace_compat
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
    assert opts.skip_udp_16kb is True
    assert opts.skip_l3_triage is True
    assert opts.skip_persist is True
    assert opts.dpi_diag is False


def test_preflight_options_quick():
    args = SimpleNamespace(quick=True, timeout=5.0)
    opts = PreflightOptions.from_args(args)
    assert opts.skip_baseline is True
    assert opts.skip_port_block is True
    assert opts.skip_ip_block is True
    assert opts.skip_prolog is False  # prolog still runs in quick mode
    assert opts.skip_udp_16kb is True
    assert opts.skip_persist is False


def test_adaptive_args_parser():
    p = argparse.ArgumentParser()
    add_adaptive_args(p)
    parsed_default = p.parse_args([])
    assert parsed_default.adaptive is True

    parsed_no_adaptive = p.parse_args(["--no-adaptive"])
    namespace_compat(parsed_no_adaptive)
    assert parsed_no_adaptive.adaptive is False
    assert parsed_no_adaptive.no_adaptive is True

    parsed_adaptive = p.parse_args(["--adaptive"])
    namespace_compat(parsed_adaptive)
    assert parsed_adaptive.adaptive is True
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


def _help(argv: list[str]) -> str:
    from io import StringIO
    from unittest.mock import patch

    import pytest

    from blockchecks.cli.parser import build_parser

    buf = StringIO()
    with patch("sys.stdout", buf), pytest.raises(SystemExit) as exc:
        build_parser().parse_args(argv)
    assert exc.value.code in (0, None)
    return buf.getvalue()


def test_scan_help_classic_deprecated_not_second_backend():
    text = _help(["scan", "--help"])
    assert "--classic" in text
    assert "Deprecated" in text or "deprecated" in text
    assert "lua_bridge" in text
    assert "second backend" not in text.lower()


def test_scan_and_full_help_have_quarantine_flags():
    scan = _help(["scan", "--help"])
    assert "--no-quarantine" in scan
    assert "--quarantine-min" in scan
    from io import StringIO
    from unittest.mock import patch

    import pytest

    from blockchecks.main import build_arg_parser

    buf = StringIO()
    with patch("sys.stdout", buf), pytest.raises(SystemExit) as exc:
        build_arg_parser().parse_args(["--help"])
    assert exc.value.code in (0, None)
    full = buf.getvalue()
    assert "--no-quarantine" in full
    assert "--quarantine-min" in full


def test_unknown_flag_and_bogus_profile_level_rejected():
    import pytest

    from blockchecks.cli.parser import build_parser

    cases = (
        ["tcp", "--not-a-flag"],
        ["scan", "--profile", "nope", "-d", "x.com"],
        ["scan", "--scan-level", "nope", "-d", "x.com"],
    )
    for argv in cases:
        with pytest.raises(SystemExit) as exc:
            build_parser().parse_args(argv)
        assert exc.value.code == 2, argv


def test_classic_and_probe_backend_classic_map_to_lua_bridge(caplog):
    import logging

    from blockchecks.cli.parser import build_parser, iter_subparsers
    from blockchecks.engine.config import resolve_probe_backend

    scan = iter_subparsers(build_parser())["scan"]
    for argv in (["--classic"], ["--probe-backend", "classic"]):
        ns = scan.parse_args(["-d", "x.com", *argv, "--max", "1"])
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            assert resolve_probe_backend(ns) == "lua_bridge"
        assert "mapping to lua_bridge" in caplog.text


def test_curl_parallel_parses_1_and_8():
    from blockchecks.cli.parser import build_parser, iter_subparsers
    from blockchecks.engine.config import MAX_CURL_PARALLEL

    assert MAX_CURL_PARALLEL == 8
    scan = iter_subparsers(build_parser())["scan"]
    for n in (1, 8):
        ns = scan.parse_args(["-d", "x.com", "--curl-parallel", str(n), "--max", "1"])
        assert ns.curl_parallel == n
