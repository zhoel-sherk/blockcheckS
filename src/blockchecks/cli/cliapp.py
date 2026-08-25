"""Parse argv with pydantic models built from cli.parser actions, then dispatch handlers."""

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
from pydantic_settings import (
    BaseSettings,
    CliApp,
    CliSubCommand,
    SettingsConfigDict,
    get_subcommand,
)

log = logging.getLogger(__name__)


_GENERATE_DEFAULT = "custom,configs"


def normalize_cli_args(argv: list[str]) -> list[str]:
    """Map ``bs --stop`` → ``bs stop`` (global graceful-stop alias)."""
    if argv and argv[0] == "--stop":
        return ["stop", *argv[1:]]
    return argv


# Handler registry — subcommand models intentionally have no cli_cmd (VPS-2).
_CMD_HANDLERS: dict[str, Any] = {}
_CLI_EXIT_CODE: int = 0
_FULL_RUN_ACTIVE: bool = False
# User config.toml loaded in main(); used by _to_namespace to fill db/out_dir.
_USER_CFG: dict[str, Any] | None = None
# Fields whose --no-<name> flag pydantic parses as negation (False) instead of
# setting True; re-applied in _dispatch_subcommand from main()'s argv capture.
_NO_FLAGS_CAPTURED: set[str] = set()
_NO_PREFIX_FIELDS = frozenset(
    {
        "no_adaptive",
        "no_preflight",
        "no_ech",
        "no_sync",
        "no_wssize",
        "no_http",
        "no_quic",
        "no_voice",
        "no_secure_dns",
        "no_auto_pin",
        "no_settle_profile",
        "no_hostlist",
        "no_common_only",
        "no_family_gates",
        "no_adaptive_weights",
        "no_write_profile",
        "no_fetch_deps",
        "no_export_on_stop",
    }
)


def _annotation_for_action(action: argparse.Action) -> Any:
    if isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction)):
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
    if action.nargs in ("+", "*"):
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
    if isinstance(action, argparse._StoreTrueAction):
        return False
    if isinstance(action, argparse._StoreFalseAction):
        return True
    if action.default is argparse.SUPPRESS:
        return None
    return action.default


def _short_letter(option: str) -> str | None:
    """Return short flag letter from ``-d`` / ``-M`` (not ``--long``)."""
    if len(option) == 2 and option.startswith("-") and not option.startswith("--"):
        return option[1]
    return None


def collect_cli_shortcuts(*parsers: argparse.ArgumentParser) -> dict[str, str | list[str]]:
    """Map kebab field names → short-flag letters from argparse option_strings."""
    shortcuts: dict[str, list[str]] = {}
    for parser in parsers:
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                continue
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
    """Restore argparse ``nargs='?' const='1'`` UX for ``--nfqws2-debug``.

    The argparse path accepts a bare ``--nfqws2-debug`` (means ``1``), but the
    pydantic CliApp model rejects a flag without a value. Inject ``1`` when the
    flag is followed by another flag or end-of-args.
    """
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


def model_from_subparser(name: str, parser: argparse.ArgumentParser) -> type[BaseModel]:
    fields: dict[str, Any] = {}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            continue
        if action.dest in ("help", "command") or not action.dest:
            continue
        if action.dest in fields and isinstance(action, argparse._StoreFalseAction):
            continue
        ann = _annotation_for_action(action)
        default = _field_default(action)
        if action.required:
            fields[action.dest] = (ann, Field(...))
        else:
            fields[action.dest] = (ann, Field(default=default))
    return create_model(name, __base__=BaseModel, **fields)


def _subparsers() -> dict[str, argparse.ArgumentParser]:
    from blockchecks.cli.parser import build_parser

    root = build_parser()
    for action in root._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def _subcommand_blurbs() -> dict[str, str]:
    """Map subcommand name → one-line help from argparse ``add_parser(..., help=)``."""
    from blockchecks.cli.parser import build_parser

    root = build_parser()
    out: dict[str, str] = {}
    for action in root._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        for choice in action._choices_actions:
            name = choice.dest
            text = (choice.help or "").strip()
            if name and text:
                out[name] = text
    return out


def _parser_blurb(name: str, blurbs: dict[str, str], fallback: str) -> str:
    return blurbs.get(name) or fallback


def _to_namespace(model: BaseModel, **extra: Any) -> argparse.Namespace:
    data = model.model_dump()
    data.update(extra)
    ns = argparse.Namespace(**data)
    # Fields the user actually passed — apply_profile must not clobber them.
    ns._explicit_cli = set(model.model_fields_set)
    # CliApp path: argparse.dispatch() calls finalize_store_args() post-parse to
    # fill None db/out_dir from config.toml / XDG defaults. CliApp bypasses
    # dispatch(), so apply it here or bs full/scan/pair would export nowhere.
    if _USER_CFG is not None:
        from blockchecks.cli.user_config import finalize_store_args

        finalize_store_args(ns, _USER_CFG)
    return ns


def _make_cmd_model(class_name: str, base: type[BaseModel], handler, doc: str = ""):
    """Parse-only subcommand model; handler runs via root ``cli_cmd`` (single dispatch)."""
    _CMD_HANDLERS[class_name] = handler
    ns: dict[str, Any] = {}
    if doc:
        ns["__doc__"] = doc
    return type(class_name, (base,), ns)


def _dispatch_subcommand(root: BaseModel) -> int:
    """Run one subcommand handler — never call sub.cli_cmd() (avoids CliApp double dispatch)."""
    sub = get_subcommand(root, is_required=False)
    if sub is None:
        return 2
    _apply_debug_flags(sub)
    # pydantic-settings 2.14 parses "--no-<field>" as negation, so fields named
    # ``no_*`` arrive False; re-apply the captured flags from main().
    for _field in _NO_FLAGS_CAPTURED:
        if hasattr(sub, _field):
            setattr(sub, _field, True)
    handler = _CMD_HANDLERS.get(type(sub).__name__)
    if handler is None:
        return 2
    return int(handler(sub))


def _apply_nfqws2_debug_env(sub: BaseModel) -> None:
    """Propagate ``--nfqws2-debug`` from the parsed subcommand into the env."""
    dbg = getattr(sub, "nfqws2_debug", None)
    if dbg is not None:
        os.environ["BLOCKCHECKS_NFQWS2_DEBUG"] = str(dbg)


def _apply_debug_flags(sub: BaseModel) -> None:
    """Apply ``--debug`` (Python+nfqws2) or nfqws2-only env from the subcommand."""
    if getattr(sub, "debug", False):
        from blockchecks.engine.log import set_debug_mode

        set_debug_mode(True)
        return
    _apply_nfqws2_debug_env(sub)


def _print_validation_error(exc: pydantic_core.ValidationError) -> int:
    """Print required-flag errors without a traceback (argparse-style exit 2)."""
    errs = exc.errors()
    if not errs:
        print("ERROR: invalid arguments", file=sys.stderr)  # noqa: print
        return 2
    e = errs[0]
    loc = ".".join(str(x) for x in e.get("loc", ()) if x != "__root__")
    msg = e.get("msg", "invalid value")
    ctx = e.get("ctx") or {}
    extra = ""
    if ctx.get("expected"):
        extra = f" (expected {ctx['expected']})"
    if loc:
        print(f"ERROR: --{loc.replace('.', ' ')}: {msg}{extra}", file=sys.stderr)  # noqa: print
    else:
        print(f"ERROR: {msg}{extra}", file=sys.stderr)  # noqa: print
    return 2


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
    """Run the resident probe server (Unix socket core + optional HTTP bridge)."""
    from blockchecks.cli.commands.serve import cmd_serve

    return cmd_serve(_to_namespace(model))


def _run_mcp(model: BaseModel) -> int:
    """Run the MCP server over stdio (bridges LLM → bs serve daemon)."""
    from blockchecks.cli.commands.mcp import cmd_mcp

    return cmd_mcp(_to_namespace(model))


def _run_preflight(model: BaseModel) -> int:
    from blockchecks.cli.commands.preflight import run_preflight_cmd
    from blockchecks.cli.parser import ensure_system_deps_or_exit

    ns = _to_namespace(model)
    ns.command = "preflight"
    if getattr(ns, "list_presets", False):
        code = 0
    else:
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


def build_cli_root() -> type[BaseSettings]:
    from blockchecks.cli.user_config import apply_parser_defaults

    subs = _subparsers()
    from blockchecks.main import build_arg_parser

    full_parser = build_arg_parser()
    # Apply config.toml defaults to the SAME parsers the pydantic models are
    # derived from (otherwise defaults silently live only on the unused `probe`
    # parser and bs full/scan/pair ignore [paths] db/out_dir + [run] ...).
    if _USER_CFG is not None:
        for sub_parser in subs.values():
            apply_parser_defaults(sub_parser, _USER_CFG)
        apply_parser_defaults(full_parser, _USER_CFG)
    shortcuts = collect_cli_shortcuts(*subs.values(), full_parser)
    raw_blurbs = _subcommand_blurbs()

    blurbs = {
        "tcp": _parser_blurb("tcp", raw_blurbs, "Single TCP strategy test (sync)"),
        "udp": _parser_blurb("udp", raw_blurbs, "Single UDP strategy test (sync)"),
        "scan": _parser_blurb("scan", raw_blurbs, "Async TCP strategy batch scan"),
        "pair": _parser_blurb("pair", raw_blurbs, "TCP x UDP pair matrix (async)"),
        "composite": _parser_blurb("composite", raw_blurbs, "Test composite nfqws2 config"),
        "bench-settle": _parser_blurb(
            "bench-settle", raw_blurbs, "Benchmark nfqws2 settle × curl timeout"
        ),
        "full": _parser_blurb("full", raw_blurbs, "Full matrix campaign (TCP/UDP/HTTP/QUIC)"),
        "stop": _parser_blurb("stop", raw_blurbs, "Gracefully stop active full/scan/pair run"),
        "serve": _parser_blurb(
            "serve", raw_blurbs, "Resident probe server (Unix socket + optional HTTP bridge)"
        ),
        "mcp": _parser_blurb(
            "mcp",
            raw_blurbs,
            "Model Context Protocol server (stdio) bridging LLM → bs serve daemon",
        ),
        "preflight": _parser_blurb(
            "preflight",
            raw_blurbs,
            "DNS/L3/stall triage + data_block triage.toml/hosts (no matrix)",
        ),
        "data-block": _parser_blurb(
            "data-block",
            raw_blurbs,
            "Export XDG provider store to a git data_block checkout",
        ),
        "harvest-batch": _parser_blurb(
            "harvest-batch",
            raw_blurbs,
            "Export top PASS strategies → dpi-tester batch.txt + manifest (+ confs)",
        ),
    }

    TcpCmd = _make_cmd_model(
        "TcpCmd", model_from_subparser("TcpArgs", subs["tcp"]), _run_tcp, blurbs["tcp"]
    )
    UdpCmd = _make_cmd_model(
        "UdpCmd", model_from_subparser("UdpArgs", subs["udp"]), _run_udp, blurbs["udp"]
    )
    ScanCmd = _make_cmd_model(
        "ScanCmd", model_from_subparser("ScanArgs", subs["scan"]), _run_scan, blurbs["scan"]
    )
    PairCmd = _make_cmd_model(
        "PairCmd", model_from_subparser("PairArgs", subs["pair"]), _run_pair, blurbs["pair"]
    )
    CompositeCmd = _make_cmd_model(
        "CompositeCmd",
        model_from_subparser("CompositeArgs", subs["composite"]),
        _run_composite,
        blurbs["composite"],
    )
    BenchCmd = _make_cmd_model(
        "BenchSettleCmd",
        model_from_subparser("BenchArgs", subs["bench-settle"]),
        _run_bench,
        blurbs["bench-settle"],
    )
    FullCmd = _make_cmd_model(
        "FullCmd", model_from_subparser("FullArgs", full_parser), _run_full, blurbs["full"]
    )
    StopCmd = _make_cmd_model(
        "StopCmd", model_from_subparser("StopArgs", subs["stop"]), _run_stop, blurbs["stop"]
    )
    ServeCmd = _make_cmd_model(
        "ServeCmd", model_from_subparser("ServeArgs", subs["serve"]), _run_serve, blurbs["serve"]
    )
    McpCmd = _make_cmd_model(
        "McpCmd", model_from_subparser("McpArgs", subs["mcp"]), _run_mcp, blurbs["mcp"]
    )
    PreflightCmd = _make_cmd_model(
        "PreflightCmd",
        model_from_subparser("PreflightArgs", subs["preflight"]),
        _run_preflight,
        blurbs["preflight"],
    )
    DataBlockCmd = _make_cmd_model(
        "DataBlockCmd",
        model_from_subparser("DataBlockArgs", subs["data-block"]),
        _run_data_block,
        blurbs["data-block"],
    )
    HarvestBatchCmd = _make_cmd_model(
        "HarvestBatchCmd",
        model_from_subparser("HarvestBatchArgs", subs["harvest-batch"]),
        _run_harvest_batch,
        blurbs["harvest-batch"],
    )

    class BlockchecksCli(BaseSettings):
        """bs — lightspeed DPI strategy tester (CliApp)."""

        model_config = SettingsConfigDict(
            cli_parse_args=True,
            cli_implicit_flags=True,
            cli_kebab_case=True,
            case_sensitive=True,
            cli_shortcuts=shortcuts,
            extra="forbid",
        )

        tcp: CliSubCommand[TcpCmd] = Field(description=blurbs["tcp"])  # type: ignore[valid-type]
        udp: CliSubCommand[UdpCmd] = Field(description=blurbs["udp"])  # type: ignore[valid-type]
        scan: CliSubCommand[ScanCmd] = Field(description=blurbs["scan"])  # type: ignore[valid-type]
        pair: CliSubCommand[PairCmd] = Field(description=blurbs["pair"])  # type: ignore[valid-type]
        composite: CliSubCommand[CompositeCmd] = Field(  # type: ignore[valid-type]
            description=blurbs["composite"]
        )
        bench_settle: CliSubCommand[BenchCmd] = Field(  # type: ignore[valid-type]
            alias="bench-settle",
            description=blurbs["bench-settle"],
        )
        full: CliSubCommand[FullCmd] = Field(description=blurbs["full"])  # type: ignore[valid-type]
        stop: CliSubCommand[StopCmd] = Field(description=blurbs["stop"])  # type: ignore[valid-type]
        serve: CliSubCommand[ServeCmd] = Field(description=blurbs["serve"])  # type: ignore[valid-type]
        mcp: CliSubCommand[McpCmd] = Field(description=blurbs["mcp"])  # type: ignore[valid-type]
        preflight: CliSubCommand[PreflightCmd] = Field(  # type: ignore[valid-type]
            description=blurbs["preflight"]
        )
        data_block: CliSubCommand[DataBlockCmd] = Field(  # type: ignore[valid-type]
            alias="data-block",
            description=blurbs["data-block"],
        )
        harvest_batch: CliSubCommand[HarvestBatchCmd] = Field(  # type: ignore[valid-type]
            alias="harvest-batch",
            description=blurbs["harvest-batch"],
        )

        def cli_cmd(self) -> int:
            global _CLI_EXIT_CODE
            _CLI_EXIT_CODE = _dispatch_subcommand(self)
            return _CLI_EXIT_CODE

    return BlockchecksCli


def main(argv: list[str] | None = None) -> int:
    """Process entry: CliApp instead of argparse.parse_args."""
    from blockchecks.cli.user_config import apply_parser_defaults, load_user_config
    from blockchecks.engine.paths import (
        apply_pycache_prefix,
        configure_logging,
        ensure_dirs,
        migrate_legacy_state_db,
    )

    apply_pycache_prefix()
    ensure_dirs()
    configure_logging()
    cfg = load_user_config()
    global _USER_CFG
    _USER_CFG = cfg
    paths_cfg = cfg.get("paths") if isinstance(cfg.get("paths"), dict) else {}
    migrate_on = True if paths_cfg.get("migrate") is None else bool(paths_cfg.get("migrate"))
    migrate_legacy_state_db(enabled=migrate_on)

    from blockchecks.cli.parser import build_parser

    probe = build_parser()
    apply_parser_defaults(probe, cfg)

    raw = list(argv) if argv is not None else None
    cli_args = (
        expand_bare_nfqws2_debug(expand_bare_generate(normalize_cli_args(raw)))
        if raw is not None
        else None
    )
    if cli_args is None:
        cli_args = expand_bare_nfqws2_debug(expand_bare_generate(normalize_cli_args(sys.argv[1:])))

    Root = build_cli_root()
    # pydantic-settings 2.14 treats "--no-<field>" as a negation, so a field
    # literally named ``no_*`` (no_wssize, no_http, ...) can never be set True
    # through the CLI (both "--no-x" and "--no-no-x" parse to False). Capture
    # the flags first; _dispatch_subcommand applies them to the subcommand.
    global _NO_FLAGS_CAPTURED
    _NO_FLAGS_CAPTURED = set()
    for _arg in cli_args or ():
        if _arg.startswith("--no-"):
            _field = _arg[2:].replace("-", "_")
            if _field in _NO_PREFIX_FIELDS:
                _NO_FLAGS_CAPTURED.add(_field)
    try:
        result = CliApp.run(Root, cli_args=cli_args)
    except SystemExit as exc:
        code = exc.code
        if isinstance(code, str):
            print(code, file=sys.stderr)  # noqa: print
            return 1
        return int(code or 0)
    except pydantic_core.ValidationError as exc:
        return _print_validation_error(exc)

    # CliApp.run dispatches via _run_cli_cmd → root.cli_cmd → _dispatch_subcommand (once).
    if isinstance(result, int):
        return result
    if _CLI_EXIT_CODE:
        return _CLI_EXIT_CODE
    sub = get_subcommand(result, is_required=False)
    if sub is None:
        log.info("bs — use a subcommand: tcp|udp|scan|pair|composite|bench-settle|full|stop|preflight|data-block")
        return 2
    return 0
