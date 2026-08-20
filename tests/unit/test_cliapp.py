"""Unit tests for CliApp argv preprocess, short flags, and subcommand blurbs."""

from __future__ import annotations

import argparse
from io import StringIO
from unittest.mock import AsyncMock, MagicMock, patch

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


def test_cli_main_string_system_exit_prints_and_returns_1():
    """A SystemExit carrying a message (e.g. active-run lock) must not crash int()."""
    from blockchecks.cli import cliapp as ca

    stderr = StringIO()

    def _boom(*_a, **_k):
        raise SystemExit("ERROR: active run already registered (pid 1, scan)")

    with patch("blockchecks.cli.cliapp.CliApp.run", side_effect=_boom):
        with patch("sys.stderr", stderr):
            code = ca.main(["scan", "-d", "discord.com"])
    assert code == 1
    assert "active run already registered" in stderr.getvalue()


@pytest.mark.unit
def test_nfqws2_debug_parsed_by_cliapp_but_env_not_set_yet():
    """The CliApp path parses --nfqws2-debug into the model but does NOT
    propagate it to BLOCKCHECKS_NFQWS2_DEBUG (only parser.dispatch does, and it
    is not reached from cliapp.main). This documents the pre-fix behavior."""
    import os

    os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)
    try:
        Root = build_cli_root()
        model = Root(_cli_parse_args=["scan", "--nfqws2-debug", "1", "--max", "1"])
        sub = get_subcommand(model, is_required=True)
        assert sub.nfqws2_debug == "1"
        assert os.environ.get("BLOCKCHECKS_NFQWS2_DEBUG") is None
    finally:
        os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)


@pytest.mark.unit
def test_nfqws2_debug_env_set_by_dispatch_legacy_path():
    """The argparse dispatch() path does set the env var."""
    import os

    from blockchecks.cli.parser import dispatch

    os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)
    try:
        ns = argparse.Namespace(nfqws2_debug="syslog", command="stop", list_presets=False)
        with patch("blockchecks.cli.commands.stop.cmd_stop", lambda _a: 0):
            dispatch(ns)
        assert os.environ.get("BLOCKCHECKS_NFQWS2_DEBUG") == "syslog"
    finally:
        os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)


@pytest.mark.unit
def test_nfqws2_debug_bare_requires_value_under_cliapp():
    """Bare --nfqws2-debug is rejected: the flag requires a value."""
    import os

    from blockchecks.cli import cliapp as ca

    os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)
    try:
        Root = build_cli_root()
        # Preprocessing expands bare --nfqws2-debug → "1" (const).
        expanded = ca.expand_bare_nfqws2_debug(["scan", "--nfqws2-debug", "--max", "1"])
        assert expanded == ["scan", "--nfqws2-debug", "1", "--max", "1"]
        model = Root(_cli_parse_args=expanded)
        sub = get_subcommand(model, is_required=True)
        assert sub.nfqws2_debug == "1"
    finally:
        os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)


@pytest.mark.unit
def test_nfqws2_debug_env_propagated_by_dispatch_subcommand():
    """F1: _dispatch_subcommand sets BLOCKCHECKS_NFQWS2_DEBUG from the model."""
    import os

    from blockchecks.cli import cliapp as ca

    os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)
    try:
        Root = build_cli_root()
        model = Root(_cli_parse_args=["scan", "--nfqws2-debug", "syslog", "--max", "1"])
        sub = get_subcommand(model, is_required=True)
        ca._apply_nfqws2_debug_env(sub)
        assert os.environ.get("BLOCKCHECKS_NFQWS2_DEBUG") == "syslog"
    finally:
        os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)


@pytest.mark.unit
def test_no_prefix_flags_set_true_by_dispatch():
    """pydantic parses --no-<field> as negation; _dispatch_subcommand must
    re-apply the captured field as True (no_http/no_quic/no_voice/...)."""
    from blockchecks.cli import cliapp as ca

    old = ca._NO_FLAGS_CAPTURED
    try:
        Root = build_cli_root()
        model = Root(_cli_parse_args=["full", "-d", "discord.com"])
        ca._NO_FLAGS_CAPTURED = {"no_quic", "no_http"}
        captured: dict[str, bool] = {}

        def handler(sub):
            for field in ("no_quic", "no_http"):
                captured[field] = bool(getattr(sub, field))
            return 0

        ca._CMD_HANDLERS["FullCmd"] = handler
        assert ca._dispatch_subcommand(model) == 0
        assert captured == {"no_quic": True, "no_http": True}
    finally:
        ca._NO_FLAGS_CAPTURED = old
        ca._CMD_HANDLERS.pop("FullCmd", None)


# ── _run_* dispatcher coverage (release: all CLI commands tested) ─────


@pytest.mark.unit
def test_run_tcp_dispatcher_delegates():
    from blockchecks.cli import cliapp as ca

    with (
        patch("blockchecks.cli.cliapp._to_namespace") as to_ns,
        patch("blockchecks.cli.parser.ensure_system_deps_or_exit", return_value=0),
        patch("blockchecks.cli.commands.tcp.cmd_tcp", return_value=3) as cmd,
    ):
        to_ns.return_value = argparse.Namespace()
        rc = ca._run_tcp(MagicMock())
    assert rc == 3
    cmd.assert_called_once()
    assert to_ns.return_value.command == "tcp"


@pytest.mark.unit
def test_run_tcp_dispatcher_deps_short_circuit():
    from blockchecks.cli import cliapp as ca

    with (
        patch("blockchecks.cli.cliapp._to_namespace"),
        patch("blockchecks.cli.parser.ensure_system_deps_or_exit", return_value=5),
        patch("blockchecks.cli.commands.tcp.cmd_tcp") as cmd,
    ):
        rc = ca._run_tcp(MagicMock())
    assert rc == 5
    cmd.assert_not_called()


@pytest.mark.unit
def test_run_udp_dispatcher_delegates():
    from blockchecks.cli import cliapp as ca

    with (
        patch("blockchecks.cli.cliapp._to_namespace") as to_ns,
        patch("blockchecks.cli.parser.ensure_system_deps_or_exit", return_value=0),
        patch("blockchecks.cli.commands.udp.cmd_udp", return_value=1),
    ):
        to_ns.return_value = argparse.Namespace()
        rc = ca._run_udp(MagicMock())
    assert rc == 1
    assert to_ns.return_value.command == "udp"


@pytest.mark.unit
def test_run_composite_dispatcher_delegates():
    from blockchecks.cli import cliapp as ca

    ns = argparse.Namespace(config="/tmp/c.conf", domains=["x.com"], parallel=2, timeout=3.0)
    with (
        patch("blockchecks.cli.cliapp._to_namespace", return_value=ns),
        patch("blockchecks.cli.parser.ensure_system_deps_or_exit", return_value=0),
        patch("blockchecks.checkers.composite_runner.run", new=AsyncMock(return_value=4)) as cr,
    ):
        rc = ca._run_composite(MagicMock())
    assert rc == 4
    cr.assert_awaited_once_with("/tmp/c.conf", ["x.com"], 2, 3.0)


@pytest.mark.unit
def test_run_bench_dispatcher_delegates():
    from blockchecks.cli import cliapp as ca

    with (
        patch("blockchecks.cli.cliapp._to_namespace") as to_ns,
        patch("blockchecks.cli.parser.ensure_system_deps_or_exit", return_value=0),
        patch(
            "blockchecks.cli.commands.bench_settle.cmd_bench_settle", new=AsyncMock(return_value=2)
        ),
    ):
        to_ns.return_value = argparse.Namespace()
        rc = ca._run_bench(MagicMock())
    assert rc == 2
    assert to_ns.return_value.command == "bench-settle"


@pytest.mark.unit
def test_run_stop_dispatcher_delegates():
    from blockchecks.cli import cliapp as ca

    ns = argparse.Namespace(force=False, wait=120.0)
    with (
        patch("blockchecks.cli.cliapp._to_namespace", return_value=ns),
        patch("blockchecks.cli.commands.stop.cmd_stop", return_value=1) as cmd,
    ):
        rc = ca._run_stop(MagicMock())
    assert rc == 1
    cmd.assert_called_once_with(ns)


@pytest.mark.unit
def test_run_full_delegates_and_guards_nesting():
    from blockchecks.cli import cliapp as ca

    ns = argparse.Namespace()
    with (
        patch("blockchecks.cli.cliapp._to_namespace", return_value=ns),
        patch("blockchecks.cli.parser.ensure_system_deps_or_exit", return_value=0),
        patch("blockchecks.main.run_full", new=AsyncMock(return_value=0)) as rf,
    ):
        rc = ca._run_full(MagicMock())
    assert rc == 0
    rf.assert_awaited_once_with(ns)

    # nested guard
    ca._FULL_RUN_ACTIVE = True
    try:
        rc2 = ca._run_full(MagicMock())
        assert rc2 == 2
    finally:
        ca._FULL_RUN_ACTIVE = False


@pytest.mark.unit
def test_print_validation_error_returns_2():
    from pydantic_core import ValidationError

    from blockchecks.cli import cliapp as ca

    err = ValidationError.from_exception_data("ScanCmd", [])
    with patch("sys.stderr", StringIO()) as out:
        rc = ca._print_validation_error(err)
    assert rc == 2
    assert "invalid arguments" in out.getvalue()
