"""pydantic CliApp entry — replaces argparse.parse_args at the process boundary.

Flag *definitions* still live in ``cli.parser`` ``add_*`` / ``build_parser``
(single source for dests). CliApp parses argv into models derived from those
actions, then dispatches to existing command handlers via Namespace.
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel, Field, create_model
from pydantic_settings import (
    BaseSettings,
    CliApp,
    CliSubCommand,
    SettingsConfigDict,
    get_subcommand,
)

_GENERATE_DEFAULT = "custom,configs"


def _annotation_for_action(action: argparse.Action) -> Any:
    if isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction)):
        return bool
    if action.type is int:
        return int | None if action.default is None else int
    if action.type is float:
        return float | None if action.default is None else float
    if action.nargs in ("+", "*"):
        return list[str] | None
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


def model_from_subparser(name: str, parser: argparse.ArgumentParser) -> type[BaseModel]:
    fields: dict[str, Any] = {}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            continue
        if action.dest in ("help", "command") or not action.dest:
            continue
        ann = _annotation_for_action(action)
        default = _field_default(action)
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
    return argparse.Namespace(**data)


def _make_cmd_model(class_name: str, base: type[BaseModel], handler, doc: str = ""):
    def cli_cmd(self) -> int:  # type: ignore[no-untyped-def]
        return handler(self)

    ns: dict[str, Any] = {"cli_cmd": cli_cmd}
    if doc:
        ns["__doc__"] = doc
    return type(class_name, (base,), ns)


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

    ns = _to_namespace(model)
    ns.command = "pair"
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
            or getattr(ns, "udp_sources", "") != "custom"
        )
    code = ensure_system_deps_or_exit(ns)
    return code or asyncio.run(cmd_pair(ns))


def _run_scan(model: BaseModel) -> int:
    from blockchecks.cli.commands.pair import cmd_pair
    from blockchecks.cli.parser import ensure_system_deps_or_exit
    from blockchecks.engine.config import CONFIGS_DIR, DEFAULT_VOICE_IP, DEFAULT_VOICE_PORT

    ns = _to_namespace(model)
    ns.command = "scan"
    if getattr(ns, "list_presets", False):
        from blockchecks.cli.presets import list_presets

        list_presets()
        return 0
    gen = getattr(ns, "generate", "")
    if gen:
        ns.tcp_sources = (
            gen if gen != _GENERATE_DEFAULT else (getattr(ns, "tcp_sources", None) or _GENERATE_DEFAULT)
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
        run_composite(ns.config, getattr(ns, "domains", None), getattr(ns, "parallel", 2), ns.timeout)
    )


def _run_bench(model: BaseModel) -> int:
    from blockchecks.cli.commands.bench_settle import cmd_bench_settle
    from blockchecks.cli.parser import ensure_system_deps_or_exit

    ns = _to_namespace(model)
    ns.command = "bench-settle"
    code = ensure_system_deps_or_exit(ns)
    return code or asyncio.run(cmd_bench_settle(ns))


def _run_full(model: BaseModel) -> int:
    from blockchecks.cli.parser import ensure_system_deps_or_exit
    from blockchecks.main import run_full

    ns = _to_namespace(model)
    ns.command = "full"
    code = ensure_system_deps_or_exit(ns)
    return code or asyncio.run(run_full(ns))


def build_cli_root() -> type[BaseSettings]:
    subs = _subparsers()
    from blockchecks.main import build_arg_parser

    full_parser = build_arg_parser()
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
        "full": _parser_blurb(
            "full", raw_blurbs, "Full matrix campaign (TCP/UDP/HTTP/QUIC)"
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

        def cli_cmd(self) -> int:
            sub = get_subcommand(self, is_required=False)
            if sub is None:
                return 2
            return int(sub.cli_cmd())

    return BlockchecksCli


def main(argv: list[str] | None = None) -> int:
    """Process entry: CliApp instead of argparse.parse_args."""
    from blockchecks.cli.user_config import apply_parser_defaults, load_user_config
    from blockchecks.engine.paths import apply_pycache_prefix, ensure_dirs, migrate_legacy_state_db

    apply_pycache_prefix()
    ensure_dirs()
    cfg = load_user_config()
    paths_cfg = cfg.get("paths") if isinstance(cfg.get("paths"), dict) else {}
    migrate_on = True if paths_cfg.get("migrate") is None else bool(paths_cfg.get("migrate"))
    migrate_legacy_state_db(enabled=migrate_on)

    from blockchecks.cli.parser import build_parser

    probe = build_parser()
    apply_parser_defaults(probe, cfg)

    raw = list(argv) if argv is not None else None
    cli_args = expand_bare_generate(raw) if raw is not None else None
    if cli_args is None:
        import sys

        cli_args = expand_bare_generate(sys.argv[1:])

    Root = build_cli_root()
    try:
        result = CliApp.run(Root, cli_args=cli_args)
    except SystemExit as exc:
        return int(exc.code or 0)

    if isinstance(result, int):
        return result
    sub = get_subcommand(result, is_required=False)
    if sub is None:
        print("bs — use a subcommand: tcp|udp|scan|pair|composite|bench-settle|full")
        return 2
    code = result.cli_cmd()
    return int(code) if code is not None else 0
