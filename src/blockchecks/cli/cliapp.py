"""Parse argv with argparse (build_parser) and dispatch handlers."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from collections.abc import Sequence
from typing import Any

log = logging.getLogger(__name__)

_GENERATE_DEFAULT = "custom,configs"

# Handler registry keyed by subcommand name (tcp, scan, full, …).
_CMD_HANDLERS: dict[str, Any] = {}
_FULL_RUN_ACTIVE: bool = False
_USER_CFG: dict[str, Any] | None = None


def normalize_cli_args(argv: list[str]) -> list[str]:
    """Map ``bs --stop`` → ``bs stop`` (global graceful-stop alias)."""
    if argv and argv[0] == "--stop":
        return ["stop", *argv[1:]]
    return argv


def expand_bare_generate(argv: Sequence[str]) -> list[str]:
    """Restore argparse ``nargs='?'`` UX: bare ``--generate`` → default sources."""
    out: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--generate":
            out.append(tok)
            nxt = argv[i + 1] if i + 1 < len(argv) else None
            if nxt is None or nxt.startswith("-"):
                out.append(_GENERATE_DEFAULT)
            else:
                out.append(nxt)
                i += 1
        else:
            out.append(tok)
        i += 1
    return out


def expand_bare_nfqws2_debug(argv: Sequence[str]) -> list[str]:
    """Restore argparse ``nargs='?' const='1'`` UX for ``--nfqws2-debug``."""
    out: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--nfqws2-debug":
            out.append(tok)
            nxt = argv[i + 1] if i + 1 < len(argv) else None
            if nxt is None or nxt.startswith("-"):
                out.append("1")
            else:
                out.append(nxt)
                i += 1
        else:
            out.append(tok)
        i += 1
    return out


def preprocess_argv(argv: list[str]) -> list[str]:
    return expand_bare_nfqws2_debug(expand_bare_generate(normalize_cli_args(argv)))


def _short_letter(option: str) -> str | None:
    if len(option) == 2 and option.startswith("-") and not option.startswith("--"):
        return option[1]
    return None


def collect_cli_shortcuts(*parsers: argparse.ArgumentParser) -> dict[str, str | list[str]]:
    """Map kebab field names → short-flag letters from argparse option_strings."""
    shortcuts: dict[str, list[str]] = {}
    for parser in parsers:
        for action in parser._actions:
            if action.dest in ("help", "command") or not action.dest:
                continue
            letters = [
                letter
                for opt in action.option_strings
                if (letter := _short_letter(opt)) is not None
            ]
            if not letters:
                continue
            target = action.dest.replace("_", "-")
            bucket = shortcuts.setdefault(target, [])
            for letter in letters:
                if letter not in bucket:
                    bucket.append(letter)
    return {k: (v[0] if len(v) == 1 else v) for k, v in shortcuts.items()}


def build_command_registry(cfg: dict[str, Any] | None = None) -> None:
    """Populate handler map from build_parser (once per cfg)."""
    from blockchecks.cli.parser import build_parser, iter_subparsers
    from blockchecks.cli.user_config import apply_parser_defaults

    _CMD_HANDLERS.clear()

    subs = iter_subparsers(build_parser())
    if cfg:
        for sub in subs.values():
            apply_parser_defaults(sub, cfg)

    _CMD_HANDLERS.update(
        {
            "tcp": _run_tcp,
            "udp": _run_udp,
            "scan": _run_scan,
            "pair": _run_pair,
            "composite": _run_composite,
            "bench-settle": _run_bench,
            "full": _run_full,
            "stop": _run_stop,
            "serve": _run_serve,
            "mcp": _run_mcp,
            "preflight": _run_preflight,
            "data-block": _run_data_block,
            "harvest-batch": _run_harvest_batch,
            "gc": _run_gc,
        }
    )


def build_cli_root() -> None:
    """Register handlers (compat name; no pydantic model tree)."""
    build_command_registry(_USER_CFG)


def parse_cli_subcommand(argv: list[str], cfg: dict[str, Any] | None = None) -> argparse.Namespace:
    """Parse argv via argparse and return the subcommand namespace."""
    from blockchecks.cli.parser import parse_cli_argv

    cfg = cfg if cfg is not None else (_USER_CFG or {})
    ns, cmd, _ = parse_cli_argv(preprocess_argv(argv), cfg)
    if not cmd:
        raise ValueError("missing subcommand")
    if cmd not in _CMD_HANDLERS:
        build_command_registry(cfg)
    return ns


def _apply_nfqws2_debug_env(sub: argparse.Namespace) -> None:
    dbg = getattr(sub, "nfqws2_debug", None)
    if dbg is not None:
        os.environ["BLOCKCHECKS_NFQWS2_DEBUG"] = str(dbg)


def _apply_debug_flags(sub: argparse.Namespace) -> None:
    if getattr(sub, "debug", False):
        from blockchecks.engine.log import set_debug_mode

        set_debug_mode(True)
        return
    _apply_nfqws2_debug_env(sub)


def dispatch_parsed(ns: argparse.Namespace, cmd: str) -> int:
    """Run handler for a parsed argparse namespace."""
    _apply_debug_flags(ns)
    if cmd not in _CMD_HANDLERS:
        build_command_registry(_USER_CFG)
    handler = _CMD_HANDLERS.get(cmd)
    if handler is None:
        return 2
    return int(handler(ns))


def _run_tcp(ns: argparse.Namespace) -> int:
    from blockchecks.cli.commands.tcp import cmd_tcp
    from blockchecks.cli.parser import ensure_system_deps_or_exit

    ns.command = "tcp"
    code = ensure_system_deps_or_exit(ns)
    return code or cmd_tcp(ns)


def _run_udp(ns: argparse.Namespace) -> int:
    from blockchecks.cli.commands.udp import cmd_udp
    from blockchecks.cli.parser import ensure_system_deps_or_exit

    ns.command = "udp"
    code = ensure_system_deps_or_exit(ns)
    return code or cmd_udp(ns)


def _run_pair(ns: argparse.Namespace) -> int:
    from blockchecks.cli.commands.pair import cmd_pair
    from blockchecks.cli.parser import ensure_system_deps_or_exit
    from blockchecks.cli.profiles import apply_profile

    ns.command = "pair"
    apply_profile(ns)
    if getattr(ns, "list_presets", False):
        from blockchecks.cli.presets import list_presets

        list_presets()
        return 0
    gen = getattr(ns, "generate", "")
    if gen and gen != _GENERATE_DEFAULT:
        ns.tcp_sources = gen
    if getattr(ns, "config", None) or getattr(ns, "udp_config", None):
        ns.generate = False
    else:
        ns.generate = bool(gen) or bool(
            getattr(ns, "tcp_sources", "") != _GENERATE_DEFAULT
            or getattr(ns, "udp_sources", "") != "custom,standard_udp"
        )
    code = ensure_system_deps_or_exit(ns)
    return code or asyncio.run(cmd_pair(ns))


def _run_scan(ns: argparse.Namespace) -> int:
    from blockchecks.cli.commands.pair import cmd_pair
    from blockchecks.cli.parser import ensure_system_deps_or_exit
    from blockchecks.cli.profiles import apply_profile
    from blockchecks.engine.config import CONFIGS_DIR, DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT

    ns.command = "scan"
    apply_profile(ns)
    if getattr(ns, "list_presets", False):
        from blockchecks.cli.presets import list_presets

        list_presets()
        return 0
    gen = getattr(ns, "generate", "")
    if gen:
        ns.tcp_sources = (
            gen
            if gen != _GENERATE_DEFAULT
            else (getattr(ns, "tcp_sources", None) or _GENERATE_DEFAULT)
        )
    ns.generate = bool(gen)
    ns.tcp_only = True
    ns.udp_sources = ""
    ns.configs_dir = CONFIGS_DIR
    ns.config = None
    ns.udp_config = None
    ns.full_voice = False
    ns.udp_bypass = False
    ns.auto_discover = None
    ns.ip = DEFAULT_VOICE_IP
    ns.port = DEFAULT_VOICE_PORT
    ns.udp_timeout = 3.0
    code = ensure_system_deps_or_exit(ns)
    return code or asyncio.run(cmd_pair(ns))


def _run_composite(ns: argparse.Namespace) -> int:
    args = ns  # dead-flag gate greps `args.<dest>` readers
    from blockchecks.checkers.composite_runner import run as run_composite
    from blockchecks.cli.parser import ensure_system_deps_or_exit
    from blockchecks.engine.config import resolve_probe_isol

    ns.command = "composite"
    code = ensure_system_deps_or_exit(ns)
    if code:
        return code
    try:
        probe_isol = resolve_probe_isol(ns)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)  # noqa: T201, PRINT
        return 1
    return asyncio.run(
        run_composite(
            args.config,
            getattr(args, "domains", None),
            args.parallel,
            args.timeout,
            probe_isol=probe_isol,
            host_qnum=args.host_qnum,
        )
    )


def _run_bench(ns: argparse.Namespace) -> int:
    from blockchecks.cli.commands.bench_settle import cmd_bench_settle
    from blockchecks.cli.parser import ensure_system_deps_or_exit

    ns.command = "bench-settle"
    code = ensure_system_deps_or_exit(ns)
    return code or asyncio.run(cmd_bench_settle(ns))


def _run_full(ns: argparse.Namespace) -> int:
    global _FULL_RUN_ACTIVE
    from blockchecks.cli.parser import ensure_system_deps_or_exit
    from blockchecks.cli.profiles import apply_profile
    from blockchecks.main import run_full

    if _FULL_RUN_ACTIVE:
        log.error("ERROR: nested bs full invocation blocked (VPS-2 guard)")
        return 2

    ns.command = "full"
    apply_profile(ns)
    code = ensure_system_deps_or_exit(ns)
    if code:
        return code
    _FULL_RUN_ACTIVE = True
    try:
        return asyncio.run(run_full(ns))
    finally:
        _FULL_RUN_ACTIVE = False


def _run_stop(ns: argparse.Namespace) -> int:
    from blockchecks.cli.commands.stop import cmd_stop

    return cmd_stop(ns)


def _run_serve(ns: argparse.Namespace) -> int:
    from blockchecks.cli.commands.serve import cmd_serve

    return cmd_serve(ns)


def _run_mcp(ns: argparse.Namespace) -> int:
    from blockchecks.cli.commands.mcp import cmd_mcp

    return cmd_mcp(ns)


def _run_preflight(ns: argparse.Namespace) -> int:
    from blockchecks.cli.commands.preflight import (
        _keep_json_stdout_clean,
        run_preflight_cmd,
    )
    from blockchecks.cli.parser import ensure_system_deps_or_exit

    ns.command = "preflight"
    if getattr(ns, "list_presets", False):
        code = 0
    else:
        # Machine contract: --json must keep stdout as pure JSON, so move the
        # console stream to stderr BEFORE dependency verification logs.
        _keep_json_stdout_clean(ns)
        code = ensure_system_deps_or_exit(ns)
    return code or run_preflight_cmd(ns)


def _run_data_block(ns: argparse.Namespace) -> int:
    from blockchecks.cli.commands.data_block import cmd_data_block

    ns.command = "data-block"
    return cmd_data_block(ns)


def _run_harvest_batch(ns: argparse.Namespace) -> int:
    from blockchecks.cli.commands.harvest_batch import cmd_harvest_batch

    ns.command = "harvest-batch"
    return cmd_harvest_batch(ns)


def _run_gc(ns: argparse.Namespace) -> int:
    from blockchecks.cli.commands.gc import cmd_gc

    ns.command = "gc"
    return cmd_gc(ns)


def main(argv: list[str] | None = None) -> int:
    """Process entry: argparse → namespace_compat → handler."""
    from blockchecks.cli.parser import build_parser, parse_cli_argv
    from blockchecks.cli.user_config import load_user_config
    from blockchecks.engine.paths import (
        apply_pycache_prefix,
        configure_logging,
        cwd_db_migrate_enabled,
        ensure_dirs,
        migrate_legacy_state_db,
    )
    from blockchecks.engine.run_deadline import validate_time_limit_args

    apply_pycache_prefix()
    ensure_dirs()
    from blockchecks.service.run_control import read_active_run

    configure_logging(active_run_reader=read_active_run)
    from blockchecks.service.netns_pool import NetNsPool

    NetNsPool.install_signal_hooks()
    cfg = load_user_config()
    global _USER_CFG
    _USER_CFG = cfg
    # Rebuild registry each main() so test patches of _run_* are not stale.
    _CMD_HANDLERS.clear()
    build_command_registry(cfg)

    paths_cfg = cfg.get("paths") if isinstance(cfg.get("paths"), dict) else {}
    raw = list(argv) if argv is not None else None
    migrate_legacy_state_db(
        enabled=cwd_db_migrate_enabled(paths_cfg)
        or "--migrate-cwd-db" in (raw if raw is not None else sys.argv[1:])
    )

    cli_args = preprocess_argv(raw) if raw is not None else preprocess_argv(sys.argv[1:])

    if cli_args and cli_args[0] == "full":
        from blockchecks.main import main as full_main

        return full_main(cli_args[1:], user_config=cfg)

    try:
        ns, cmd, parser = parse_cli_argv(cli_args, cfg)
    except SystemExit as exc:
        code = exc.code
        return int(code or 0) if isinstance(code, int) else 2

    if getattr(ns, "migrate_cwd_db", False):
        migrate_legacy_state_db(enabled=True)

    if cmd is None:
        build_parser().print_help()
        return 1

    validate_time_limit_args(parser, ns)

    try:
        return dispatch_parsed(ns, cmd)
    except SystemExit as exc:
        code = exc.code
        if isinstance(code, str):
            print(code, file=sys.stderr)  # noqa: T201, print
            return 1
        return int(code or 0)
