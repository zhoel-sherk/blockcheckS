"""Parse argv with argparse (build_parser), project to pydantic, dispatch handlers."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from collections.abc import Sequence
from typing import Any, Literal

import pydantic_core
from pydantic import BaseModel, Field, create_model

log = logging.getLogger(__name__)

_GENERATE_DEFAULT = "custom,configs"

# Handler registry keyed by subcommand name (tcp, scan, full, …).
_CMD_HANDLERS: dict[str, Any] = {}
_MODEL_BY_CMD: dict[str, type[BaseModel]] = {}
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


def _is_bool_action(action: argparse.Action) -> bool:
    if isinstance(action.default, bool):
        return True
    return action.nargs == 0 and action.const in (True, False)


def _field_type_from_action(action: argparse.Action) -> Any:
    if _is_bool_action(action):
        return bool
    if (chs := action.choices) and all(isinstance(c, str) for c in chs):
        lit = Literal.__getitem__(tuple(chs))
        return lit | None if action.default is None and not action.required else lit
    if action.type is int:
        return int if action.required else (int | None if action.default is None else int)
    if action.type is float:
        return float if action.required else (float | None if action.default is None else float)
    if isinstance(action, argparse._AppendAction):
        return list[str] | None if action.default is None else list[str]
    if action.nargs == "+":
        return list[str] if action.required else (list[str] | None)
    if action.nargs in ("*",):
        return list[str]
    if action.required:
        return str
    if action.default is None:
        return str | None
    if isinstance(action.default, bool):
        return bool
    if isinstance(action.default, int):
        return int
    if isinstance(action.default, float):
        return float
    return str


def _field_default(action: argparse.Action) -> Any:
    if _is_bool_action(action) and action.default is argparse.SUPPRESS:
        return False
    if action.default is argparse.SUPPRESS:
        return None
    return action.default


def model_from_parser(name: str, parser: argparse.ArgumentParser) -> type[BaseModel]:
    """Build a pydantic model from argparse action metadata (public fields only)."""
    fields: dict[str, Any] = {}
    for action in parser._actions:
        if action.dest in ("help", "command") or not action.dest:
            continue
        if action.dest in fields:
            continue
        ann = _field_type_from_action(action)
        default = _field_default(action)
        if action.required:
            fields[action.dest] = (ann, Field(...))
        else:
            fields[action.dest] = (ann, Field(default=default))
    return create_model(name, __base__=BaseModel, **fields)


def _subcommand_blurbs() -> dict[str, str]:
    from blockchecks.cli.parser import build_parser, iter_subparsers

    blurbs: dict[str, str] = {}
    for name, sub in iter_subparsers(build_parser()).items():
        text = (sub.description or "").strip()
        if not text:
            for action in sub._actions:
                if action.dest == "help" and action.help:
                    text = action.help.strip()
                    break
        if text:
            blurbs[name] = text
    return blurbs


def _register_cmd(name: str, parser: argparse.ArgumentParser, handler, model_name: str) -> None:
    _CMD_HANDLERS[name] = handler
    _MODEL_BY_CMD[name] = model_from_parser(model_name, parser)


def build_command_registry(cfg: dict[str, Any] | None = None) -> None:
    """Populate handler + pydantic model maps from build_parser (once per cfg)."""
    from blockchecks.cli.parser import build_parser, iter_subparsers
    from blockchecks.cli.user_config import apply_parser_defaults
    from blockchecks.main import build_arg_parser

    _CMD_HANDLERS.clear()
    _MODEL_BY_CMD.clear()

    subs = iter_subparsers(build_parser())
    if cfg:
        for sub in subs.values():
            apply_parser_defaults(sub, cfg)
    full_parser = build_arg_parser(cfg)
    blurbs = _subcommand_blurbs()

    _register_cmd("tcp", subs["tcp"], _run_tcp, "TcpArgs")
    _register_cmd("udp", subs["udp"], _run_udp, "UdpArgs")
    _register_cmd("scan", subs["scan"], _run_scan, "ScanArgs")
    _register_cmd("pair", subs["pair"], _run_pair, "PairArgs")
    _register_cmd("composite", subs["composite"], _run_composite, "CompositeArgs")
    _register_cmd("bench-settle", subs["bench-settle"], _run_bench, "BenchArgs")
    _register_cmd("full", full_parser, _run_full, "FullArgs")
    _register_cmd("stop", subs["stop"], _run_stop, "StopArgs")
    _register_cmd("serve", subs["serve"], _run_serve, "ServeArgs")
    _register_cmd("mcp", subs["mcp"], _run_mcp, "McpArgs")
    _register_cmd("preflight", subs["preflight"], _run_preflight, "PreflightArgs")
    _register_cmd("data-block", subs["data-block"], _run_data_block, "DataBlockArgs")
    _register_cmd("harvest-batch", subs["harvest-batch"], _run_harvest_batch, "HarvestBatchArgs")
    _register_cmd("gc", subs["gc"], _run_gc, "GcArgs")
    _ = blurbs  # blurbs retained for help text parity tests


def build_cli_root() -> type[BaseModel]:
    """Backward-compat: return a marker type; parsing uses argparse + model_validate."""
    build_command_registry(_USER_CFG)
    return _MODEL_BY_CMD.get("scan") or model_from_parser("Empty", argparse.ArgumentParser())


def parse_cli_subcommand(argv: list[str], cfg: dict[str, Any] | None = None) -> BaseModel:
    """Parse argv via argparse and return the validated subcommand pydantic model."""
    from blockchecks.cli.parser import parse_cli_argv

    cfg = cfg if cfg is not None else (_USER_CFG or {})
    ns, cmd, _ = parse_cli_argv(preprocess_argv(argv), cfg)
    if not cmd:
        raise ValueError("missing subcommand")
    if cmd not in _MODEL_BY_CMD:
        build_command_registry(cfg)
    model_cls = _MODEL_BY_CMD[cmd]
    return model_cls.model_validate(vars(ns))


def _to_namespace(model: BaseModel, **extra: Any) -> argparse.Namespace:
    data = model.model_dump()
    data.update(extra)
    ns = argparse.Namespace(**data)
    from blockchecks.cli.parser import namespace_compat

    namespace_compat(ns)
    ns._explicit_cli = set(model.model_fields_set)
    if _USER_CFG is not None:
        from blockchecks.cli.user_config import finalize_store_args

        finalize_store_args(ns, _USER_CFG)
    return ns


def _apply_nfqws2_debug_env(sub: BaseModel | argparse.Namespace) -> None:
    dbg = getattr(sub, "nfqws2_debug", None)
    if dbg is not None:
        os.environ["BLOCKCHECKS_NFQWS2_DEBUG"] = str(dbg)


def _apply_debug_flags(sub: BaseModel | argparse.Namespace) -> None:
    if getattr(sub, "debug", False):
        from blockchecks.engine.log import set_debug_mode

        set_debug_mode(True)
        return
    _apply_nfqws2_debug_env(sub)


def _print_validation_error(exc: pydantic_core.ValidationError) -> int:
    errs = exc.errors()
    if not errs:
        print("ERROR: invalid arguments", file=sys.stderr)  # noqa: T201, print
        return 2
    e = errs[0]
    loc = ".".join(str(x) for x in e.get("loc", ()) if x != "__root__")
    msg = e.get("msg", "invalid value")
    ctx = e.get("ctx") or {}
    extra = ""
    if ctx.get("expected"):
        extra = f" (expected {ctx['expected']})"
    if loc:
        print(f"ERROR: --{loc.replace('.', ' ')}: {msg}{extra}", file=sys.stderr)  # noqa: T201, print
    else:
        print(f"ERROR: {msg}{extra}", file=sys.stderr)  # noqa: T201, print
    return 2


def dispatch_parsed(ns: argparse.Namespace, cmd: str) -> int:
    """Run handler for parsed namespace (pydantic projection + legacy handlers)."""
    _apply_debug_flags(ns)
    if cmd not in _CMD_HANDLERS:
        build_command_registry(_USER_CFG)
    handler = _CMD_HANDLERS.get(cmd)
    if handler is None:
        return 2
    model_cls = _MODEL_BY_CMD[cmd]
    try:
        model = model_cls.model_validate(vars(ns))
    except pydantic_core.ValidationError as exc:
        return _print_validation_error(exc)
    return int(handler(model))


def _run_tcp(model: BaseModel) -> int:
    from blockchecks.cli.commands.tcp import cmd_tcp
    from blockchecks.cli.parser import ensure_system_deps_or_exit

    ns = _to_namespace(model)
    ns.command = "tcp"
    code = ensure_system_deps_or_exit(ns)
    return code or cmd_tcp(ns)


def _run_udp(model: BaseModel) -> int:
    from blockchecks.cli.commands.udp import cmd_udp
    from blockchecks.cli.parser import ensure_system_deps_or_exit

    ns = _to_namespace(model)
    ns.command = "udp"
    code = ensure_system_deps_or_exit(ns)
    return code or cmd_udp(ns)


def _run_pair(model: BaseModel) -> int:
    from blockchecks.cli.commands.pair import cmd_pair
    from blockchecks.cli.parser import ensure_system_deps_or_exit
    from blockchecks.cli.profiles import apply_profile

    ns = _to_namespace(model)
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


def _run_scan(model: BaseModel) -> int:
    from blockchecks.cli.commands.pair import cmd_pair
    from blockchecks.cli.parser import ensure_system_deps_or_exit
    from blockchecks.cli.profiles import apply_profile
    from blockchecks.engine.config import CONFIGS_DIR, DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT

    ns = _to_namespace(model)
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


def _run_composite(model: BaseModel) -> int:
    from blockchecks.checkers.composite_runner import run as run_composite
    from blockchecks.cli.parser import ensure_system_deps_or_exit

    ns = _to_namespace(model)
    ns.command = "composite"
    code = ensure_system_deps_or_exit(ns)
    if code:
        return code
    return asyncio.run(
        run_composite(
            ns.config, getattr(ns, "domains", None), getattr(ns, "parallel", 2), ns.timeout
        )
    )


def _run_bench(model: BaseModel) -> int:
    from blockchecks.cli.commands.bench_settle import cmd_bench_settle
    from blockchecks.cli.parser import ensure_system_deps_or_exit

    ns = _to_namespace(model)
    ns.command = "bench-settle"
    code = ensure_system_deps_or_exit(ns)
    return code or asyncio.run(cmd_bench_settle(ns))


def _run_full(model: BaseModel) -> int:
    global _FULL_RUN_ACTIVE
    from blockchecks.cli.parser import ensure_system_deps_or_exit
    from blockchecks.cli.profiles import apply_profile
    from blockchecks.main import run_full

    if _FULL_RUN_ACTIVE:
        log.error("ERROR: nested bs full invocation blocked (VPS-2 guard)")
        return 2

    ns = _to_namespace(model)
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


def _run_stop(model: BaseModel) -> int:
    from blockchecks.cli.commands.stop import cmd_stop

    return cmd_stop(_to_namespace(model))


def _run_serve(model: BaseModel) -> int:
    from blockchecks.cli.commands.serve import cmd_serve

    return cmd_serve(_to_namespace(model))


def _run_mcp(model: BaseModel) -> int:
    from blockchecks.cli.commands.mcp import cmd_mcp

    return cmd_mcp(_to_namespace(model))


def _run_preflight(model: BaseModel) -> int:
    from blockchecks.cli.commands.preflight import (
        _keep_json_stdout_clean,
        run_preflight_cmd,
    )
    from blockchecks.cli.parser import ensure_system_deps_or_exit

    ns = _to_namespace(model)
    ns.command = "preflight"
    if getattr(ns, "list_presets", False):
        code = 0
    else:
        # Machine contract: --json must keep stdout as pure JSON, so move the
        # console stream to stderr BEFORE dependency verification logs.
        _keep_json_stdout_clean(ns)
        code = ensure_system_deps_or_exit(ns)
    return code or run_preflight_cmd(ns)


def _run_data_block(model: BaseModel) -> int:
    from blockchecks.cli.commands.data_block import cmd_data_block

    ns = _to_namespace(model)
    ns.command = "data-block"
    return cmd_data_block(ns)


def _run_harvest_batch(model: BaseModel) -> int:
    from blockchecks.cli.commands.harvest_batch import cmd_harvest_batch

    ns = _to_namespace(model)
    ns.command = "harvest-batch"
    return cmd_harvest_batch(ns)


def _run_gc(model: BaseModel) -> int:
    from blockchecks.cli.commands.gc import cmd_gc

    ns = _to_namespace(model)
    ns.command = "gc"
    return cmd_gc(ns)


def main(argv: list[str] | None = None) -> int:
    """Process entry: argparse → namespace_compat → model_validate → handler."""
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
    configure_logging()
    from blockchecks.service.netns_pool import NetNsPool

    NetNsPool.install_signal_hooks()
    cfg = load_user_config()
    global _USER_CFG
    _USER_CFG = cfg
    # Пересобираем реестр на каждый запуск main(): тесты патчат handler-функции
    # в модуле ПОСЛЕ первого построения, а замороженные ссылки делают патчи
    # мёртвыми (ARC-7). Построение дешёвое — это только словарь ссылок.
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
    except pydantic_core.ValidationError as exc:
        return _print_validation_error(exc)
