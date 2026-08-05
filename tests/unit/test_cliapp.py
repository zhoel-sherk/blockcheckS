"""Unit tests for CliApp argv preprocess, short flags, and subcommand blurbs."""

from __future__ import annotations

from io import StringIO
from unittest.mock import patch

import pytest
from pydantic_settings import CliApp, get_subcommand

from blockchecks.cli.cliapp import (
    _GENERATE_DEFAULT,
    build_cli_root,
    collect_cli_shortcuts,
    expand_bare_generate,
)


@pytest.mark.unit
def test_expand_bare_generate_inserts_default():
    assert expand_bare_generate(["scan", "--generate"]) == [
        "scan",
        "--generate",
        _GENERATE_DEFAULT,
    ]
    assert expand_bare_generate(["scan", "--generate", "--parallel", "4"]) == [
        "scan",
        "--generate",
        _GENERATE_DEFAULT,
        "--parallel",
        "4",
    ]


@pytest.mark.unit
def test_expand_bare_generate_keeps_explicit_value():
    assert expand_bare_generate(["scan", "--generate", "fake,configs"]) == [
        "scan",
        "--generate",
        "fake,configs",
    ]


@pytest.mark.unit
def test_collect_cli_shortcuts_includes_domain_and_strategy_preset():
    import argparse

    from blockchecks.cli.parser import build_parser
    from blockchecks.main import build_arg_parser

    root = build_parser()
    subs = {}
    for action in root._actions:
        if isinstance(action, argparse._SubParsersAction):
            subs = dict(action.choices)
            break
    shortcuts = collect_cli_shortcuts(*subs.values(), build_arg_parser())
    assert shortcuts.get("domain") == "d"
    assert shortcuts.get("strategy-preset") == "M"
    assert shortcuts.get("config") == "c"


@pytest.mark.unit
def test_scan_short_flags_parse_domain_and_preset():
    Root = build_cli_root()
    model = Root(
        _cli_parse_args=expand_bare_generate(
            ["scan", "-d", "discord.com", "-M", "gp-verified", "--max", "1"]
        )
    )
    sub = get_subcommand(model, is_required=True)
    assert sub.domain == "discord.com"
    assert sub.strategy_preset == "gp-verified"
    assert sub.max == 1


@pytest.mark.unit
def test_scan_bare_generate_preprocessed():
    Root = build_cli_root()
    model = Root(_cli_parse_args=expand_bare_generate(["scan", "--generate", "--max", "1"]))
    sub = get_subcommand(model, is_required=True)
    assert sub.generate == _GENERATE_DEFAULT


@pytest.mark.unit
def test_composite_short_config_flag():
    Root = build_cli_root()
    model = Root(_cli_parse_args=["composite", "-c", "/tmp/x.conf"])
    sub = get_subcommand(model, is_required=True)
    assert sub.config == "/tmp/x.conf"


@pytest.mark.unit
def test_root_help_includes_subcommand_blurbs():
    Root = build_cli_root()
    buf = StringIO()
    with patch("sys.stdout", buf), pytest.raises(SystemExit) as exc:
        CliApp.run(Root, cli_args=["--help"])
    assert exc.value.code in (0, None)
    help_text = buf.getvalue()
    assert "Async TCP strategy batch scan" in help_text
    assert "TCP x UDP pair matrix" in help_text or "TCP×UDP" in help_text
    assert "Single TCP strategy test" in help_text


@pytest.mark.unit
def test_scan_help_shows_short_flags():
    Root = build_cli_root()
    buf = StringIO()
    with patch("sys.stdout", buf), pytest.raises(SystemExit) as exc:
        CliApp.run(Root, cli_args=["scan", "--help"])
    assert exc.value.code in (0, None)
    help_text = buf.getvalue()
    assert "-d" in help_text
    assert "-M" in help_text or "strategy-preset" in help_text


@pytest.mark.unit
def test_subcommand_models_have_no_cli_cmd():
    """VPS-2: subcommand parse models must not expose cli_cmd (single root dispatch)."""
    Root = build_cli_root()
    model = Root(_cli_parse_args=["scan", "--max", "1"])
    sub = get_subcommand(model, is_required=True)
    assert not callable(getattr(type(sub), "cli_cmd", None))


@pytest.mark.unit
def test_cli_dispatches_scan_handler_once():
    """VPS-2: CliApp.run must invoke scan handler exactly once."""
    from blockchecks.cli import cliapp as ca

    calls: list[int] = []

    def trace_scan(_model):
        calls.append(1)
        return 0

    Root = build_cli_root()
    ca._CMD_HANDLERS["ScanCmd"] = trace_scan
    with patch("blockchecks.cli.parser.ensure_system_deps_or_exit", lambda _a: 0):
        CliApp.run(Root, cli_args=["scan", "--max", "1", "--skip-deps-check"])
    assert len(calls) == 1


@pytest.mark.unit
def test_cli_main_returns_handler_exit_code():
    from blockchecks.cli import cliapp as ca

    with patch("blockchecks.cli.cliapp._run_scan", return_value=7):
        with patch("blockchecks.cli.parser.ensure_system_deps_or_exit", lambda _a: 0):
            code = ca.main(["scan", "-d", "discord.com", "--max", "1", "--skip-deps-check"])
    assert code == 7
