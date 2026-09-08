"""Unit tests for CliApp argv preprocess, short flags, and subcommand blurbs."""

from __future__ import annotations

import argparse
from io import StringIO
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.cli.cliapp import (
    _GENERATE_DEFAULT,
    _apply_debug_flags,
    _apply_nfqws2_debug_env,
    build_command_registry,
    collect_cli_shortcuts,
    dispatch_parsed,
    expand_bare_generate,
    parse_cli_subcommand,
)
from blockchecks.cli.parser import build_parser, iter_subparsers, namespace_compat
from blockchecks.engine.log import debug_status, set_debug_mode


@pytest.fixture(autouse=True)
def _cli_registry():
    build_command_registry({})
    yield


def _parse(argv: list[str]):
    return parse_cli_subcommand(expand_bare_generate(argv))


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
    from blockchecks.main import build_arg_parser

    subs = iter_subparsers(build_parser())
    shortcuts = collect_cli_shortcuts(*subs.values(), build_arg_parser())
    assert shortcuts.get("domain") == "d"
    assert shortcuts.get("strategy-preset") == "M"
    assert shortcuts.get("config") == "c"


@pytest.mark.unit
def test_scan_short_flags_parse_domain_and_preset():
    sub = _parse(["scan", "-d", "discord.com", "-M", "gp-verified", "--max", "1"])
    assert sub.domain == ["discord.com"]
    assert sub.strategy_preset == "gp-verified"
    assert sub.max == 1


@pytest.mark.unit
def test_scan_bare_generate_preprocessed():
    sub = _parse(["scan", "--generate", "--max", "1"])
    assert sub.generate == _GENERATE_DEFAULT


@pytest.mark.unit
def test_composite_short_config_flag():
    sub = _parse(["composite", "-c", "/tmp/x.conf"])
    assert sub.config == "/tmp/x.conf"


@pytest.mark.unit
def test_root_help_includes_subcommand_blurbs():
    buf = StringIO()
    with patch("sys.stdout", buf), pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--help"])
    assert exc.value.code in (0, None)
    help_text = buf.getvalue()
    assert "Async TCP strategy batch scan" in help_text
    assert "TCP x UDP pair matrix" in help_text or "TCP×UDP" in help_text
    assert "Single TCP strategy test" in help_text
    assert "triage.toml" in help_text or "preflight" in help_text.lower()
    assert "data-block" in help_text.lower() or "data_block" in help_text.lower()
    assert "gc" in help_text.lower()


@pytest.mark.unit
def test_data_block_export_parses():
    sub = _parse(["data-block", "--git", "--out", "/tmp/db"])
    assert sub.git is True
    assert sub.out == "/tmp/db"


@pytest.mark.unit
def test_gc_parses_dry_run():
    sub = _parse(["gc", "--max-age-days", "7"])
    assert sub.max_age_days == 7.0
    assert sub.apply is False


@pytest.mark.unit
def test_tcp_help_documents_host_default():
    buf = StringIO()
    with patch("sys.stdout", buf), pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["tcp", "--help"])
    assert exc.value.code in (0, None)
    help_text = buf.getvalue()
    assert "HOST" in help_text
    assert "not netns" in help_text.lower()
    assert "Without --ns" in help_text


@pytest.mark.unit
def test_scan_help_shows_short_flags():
    buf = StringIO()
    with patch("sys.stdout", buf), pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["scan", "--help"])
    assert exc.value.code in (0, None)
    help_text = buf.getvalue()
    assert "-d" in help_text
    assert "-M" in help_text or "strategy-preset" in help_text


@pytest.mark.unit
def test_subcommand_models_have_no_cli_cmd():
    """VPS-2: subcommand parse models must not expose cli_cmd (single root dispatch)."""
    sub = _parse(["scan", "--max", "1"])
    assert not callable(getattr(type(sub), "cli_cmd", None))


@pytest.mark.unit
def test_scan_cliapp_adaptive_on_by_default():
    sub = _parse(["scan", "--max", "1"])
    assert sub.adaptive is True


@pytest.mark.unit
def test_scan_adaptive_and_no_adaptive_argparse_cliapp_parity():
    """--adaptive / --no-adaptive match between argparse Namespace and CliApp projection."""
    scan_parser = iter_subparsers(build_parser())["scan"]
    for flag, expect_adaptive in (("--no-adaptive", False), ("--adaptive", True)):
        ns = scan_parser.parse_args([flag, "-d", "discord.com", "--max", "1"])
        namespace_compat(ns)
        assert ns.adaptive is expect_adaptive
        assert ns.no_adaptive is (not expect_adaptive)
        sub = _parse(["scan", flag, "-d", "discord.com", "--max", "1"])
        assert sub.adaptive is expect_adaptive


@pytest.mark.unit
def test_cli_dispatches_scan_handler_once():
    """VPS-2: main() must invoke scan handler exactly once."""
    from blockchecks.cli import cliapp as ca

    calls: list[int] = []

    def trace_scan(_model):
        calls.append(1)
        return 0

    with (
        patch("blockchecks.cli.cliapp._run_scan", side_effect=trace_scan),
        patch("blockchecks.cli.parser.ensure_system_deps_or_exit", lambda _a: 0),
        patch("blockchecks.cli.commands.pair.cmd_pair", new=AsyncMock(return_value=0)),
    ):
        rc = ca.main(["scan", "-d", "discord.com", "--max", "1", "--skip-deps-check"])
        print("DBG rc:", rc)
    assert len(calls) == 1, f"calls={len(calls)}"


@pytest.mark.unit
def test_cli_main_returns_handler_exit_code():
    from blockchecks.cli import cliapp as ca

    with (
        patch("blockchecks.cli.cliapp._run_scan", return_value=7),
        patch("blockchecks.cli.parser.ensure_system_deps_or_exit", lambda _a: 0),
        patch("blockchecks.cli.commands.pair.cmd_pair", new=AsyncMock(return_value=7)),
    ):
        code = ca.main(["scan", "-d", "discord.com", "--max", "1", "--skip-deps-check"])
    assert code == 7


def test_cli_main_string_system_exit_prints_and_returns_1():
    """A SystemExit carrying a message (e.g. active-run lock) must not crash int()."""
    from blockchecks.cli import cliapp as ca

    stderr = StringIO()

    def _boom(*_a, **_k):
        raise SystemExit("ERROR: active run already registered (pid 1, scan)")

    with patch("blockchecks.cli.cliapp.dispatch_parsed", side_effect=_boom):
        with patch("blockchecks.cli.parser.parse_cli_argv") as parse_mock:
            parse_mock.return_value = (
                argparse.Namespace(command="scan"),
                "scan",
                build_parser(),
            )
            with patch("sys.stderr", stderr):
                code = ca.main(["scan", "-d", "discord.com"])
    assert code == 1
    assert "active run already registered" in stderr.getvalue()


@pytest.mark.unit
def test_nfqws2_debug_parsed_by_cliapp_but_env_not_set_yet():
    """Parsing --nfqws2-debug does not set env until _apply_debug_flags runs."""
    import os

    os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)
    try:
        sub = _parse(["scan", "--nfqws2-debug", "1", "--max", "1"])
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
    """Bare --nfqws2-debug expands to const ``1`` (argparse nargs='?' parity)."""
    import os

    from blockchecks.cli import cliapp as ca

    os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)
    try:
        expanded = ca.expand_bare_nfqws2_debug(["scan", "--nfqws2-debug", "--max", "1"])
        assert expanded == ["scan", "--nfqws2-debug", "1", "--max", "1"]
        sub = _parse(expanded)
        assert sub.nfqws2_debug == "1"
    finally:
        os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)


@pytest.mark.unit
def test_nfqws2_debug_env_propagated_by_dispatch_subcommand():
    """dispatch_parsed / _apply_debug_flags sets BLOCKCHECKS_NFQWS2_DEBUG."""
    import os

    os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)
    try:
        sub = _parse(["scan", "--nfqws2-debug", "syslog", "--max", "1"])
        _apply_nfqws2_debug_env(sub)
        assert os.environ.get("BLOCKCHECKS_NFQWS2_DEBUG") == "syslog"
    finally:
        os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)


@pytest.mark.unit
def test_debug_flag_calls_set_debug_mode():
    """``--debug`` is the unified toggle (Python DEBUG + nfqws2)."""
    import os

    os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)
    os.environ.pop("BLOCKCHECKS_LOG_LEVEL", None)
    try:
        sub = _parse(["scan", "--debug", "--max", "1"])
        assert sub.debug is True
        _apply_debug_flags(sub)
        st = debug_status()
        assert st["enabled"] is True
        assert os.environ.get("BLOCKCHECKS_NFQWS2_DEBUG") == "1"
        assert os.environ.get("BLOCKCHECKS_LOG_LEVEL") == "DEBUG"
    finally:
        set_debug_mode(False)
        os.environ.pop("BLOCKCHECKS_NFQWS2_DEBUG", None)
        os.environ.pop("BLOCKCHECKS_LOG_LEVEL", None)


@pytest.mark.unit
def test_no_prefix_flags_set_true_by_namespace_compat():
    """BooleanOptionalAction + namespace_compat sets legacy no_http/no_quic."""
    from blockchecks.main import build_arg_parser

    ns = build_arg_parser().parse_args(["-d", "discord.com", "--no-http", "--no-quic"])
    namespace_compat(ns)
    assert ns.no_http is True
    assert ns.no_quic is True
    captured: dict[str, bool] = {}

    def handler(model):
        from blockchecks.cli.cliapp import _to_namespace

        n = _to_namespace(model)
        captured["no_http"] = bool(n.no_http)
        captured["no_quic"] = bool(n.no_quic)
        return 0

    from blockchecks.cli import cliapp as ca

    ca._CMD_HANDLERS["full"] = handler
    ns.command = "full"
    assert dispatch_parsed(ns, "full") == 0
    assert captured == {"no_http": True, "no_quic": True}


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
    prev_active = ca._FULL_RUN_ACTIVE
    try:
        ca._FULL_RUN_ACTIVE = True
        rc2 = ca._run_full(MagicMock())
        assert rc2 == 2
    finally:
        ca._FULL_RUN_ACTIVE = prev_active


@pytest.mark.unit
def test_print_validation_error_returns_2():
    from pydantic_core import ValidationError

    from blockchecks.cli import cliapp as ca

    err = ValidationError.from_exception_data("ScanCmd", [])
    with patch("sys.stderr", StringIO()) as out:
        rc = ca._print_validation_error(err)
    assert rc == 2
    assert "invalid arguments" in out.getvalue()


@pytest.mark.unit
def test_invalid_scan_level_rejected():
    with pytest.raises(SystemExit):
        _parse(["scan", "--scan-level", "nope", "-d", "x.com"])


@pytest.mark.unit
def test_warn_live_cli_flags_domains_file_overrides(caplog):
    from types import SimpleNamespace

    from blockchecks.cli.parser import warn_live_cli_flags

    caplog.set_level("WARNING")
    args = SimpleNamespace(
        domains_file="/tmp/n.txt",
        domain="youtube.com",
        preset="coverage",
        classic=True,
        probe_backend=None,
    )
    warn_live_cli_flags(args)
    text = caplog.text
    assert "overrides -d" in text
    assert "overrides --preset" in text
    assert "classic" in text.lower()
    assert "lua_bridge" in text


@pytest.mark.unit
def test_require_passwordless_sudo_exit_2(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from blockchecks.cli.parser import (
        ensure_system_deps_or_exit,
        require_passwordless_sudo,
    )

    monkeypatch.setattr("blockchecks.cli.parser.os.geteuid", lambda: 1000)
    monkeypatch.setattr(
        "blockchecks.cli.parser.subprocess.run",
        lambda *_a, **_k: MagicMock(returncode=1, stderr="a password is required", stdout=""),
    )
    assert require_passwordless_sudo() == 2
    args = SimpleNamespace(
        skip_deps_check=True,
        domains_file=None,
        domain="",
        preset=None,
        classic=False,
        probe_backend=None,
    )
    assert ensure_system_deps_or_exit(args) == 2


@pytest.mark.unit
def test_require_passwordless_sudo_root_skips(monkeypatch):
    from blockchecks.cli.parser import require_passwordless_sudo

    monkeypatch.setattr("blockchecks.cli.parser.os.geteuid", lambda: 0)

    def boom(*_a, **_k):
        raise AssertionError("sudo -n must not run as root")

    monkeypatch.setattr("blockchecks.cli.parser.subprocess.run", boom)
    assert require_passwordless_sudo() == 0


@pytest.mark.unit
def test_invalid_profile_rejected():
    with pytest.raises(SystemExit):
        _parse(["scan", "--profile", "nope", "-d", "x.com"])


@pytest.mark.unit
def test_warn_live_cli_flags_accepts_repeatable_scan_domain():
    from blockchecks.cli.parser import warn_live_cli_flags

    ns = _parse(["scan", "-d", "youtube.com", "-d", "discord.com"])
    warn_live_cli_flags(ns)
