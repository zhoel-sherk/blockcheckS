"""Dead CLI flag + consistency gates — policy in [tool.blockchecks.dead_flags].

Uses live argparse surfaces (after helper expansion) plus source text search
for dest reads (`args.X` / getattr). Equivalent to an AST gate over the
effective CLI, without false negatives from add_* helpers.
"""

from __future__ import annotations

import argparse
import re

import pytest
from tests.unit._quality_config import PROJECT_ROOT, tool_section

pytestmark = [pytest.mark.unit, pytest.mark.quality]


def _dest_mentioned(src: str, dest: str) -> bool:
    if re.search(rf"\bargs\.{re.escape(dest)}\b", src):
        return True
    if re.search(rf"getattr\(\s*args\s*,\s*[\"']{re.escape(dest)}[\"']", src):
        return True
    if re.search(rf"hasattr\(\s*args\s*,\s*[\"']{re.escape(dest)}[\"']", src):
        return True
    # Namespace assignment in wrappers (scan→pair)
    return bool(re.search(rf"\ba\.{re.escape(dest)}\b", src))


def _subparser_dests(parser: argparse.ArgumentParser) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        for name, sub in action.choices.items():
            dests = {
                a.dest
                for a in sub._actions
                if a.dest
                and not isinstance(a, argparse._SubParsersAction)
                and a.option_strings  # skip positional-only if any without opts? keep all
            }
            # Include positionals too
            dests |= {
                a.dest
                for a in sub._actions
                if a.dest and not isinstance(a, argparse._SubParsersAction)
            }
            out[name] = dests
    return out


def _read_bundle(paths: list[str]) -> str:
    chunks: list[str] = []
    for rel in paths:
        p = PROJECT_ROOT / rel
        if p.is_file():
            chunks.append(p.read_text(encoding="utf-8"))
    return "\n".join(chunks)


@pytest.mark.parametrize("command", ["tcp", "udp", "scan", "pair", "composite", "bench-settle", "stop"])
def test_no_dead_cli_flags(command: str) -> None:
    from blockchecks.cli.parser import build_parser

    cfg = tool_section("tool", "blockchecks", "dead_flags")
    ignore = set(cfg.get("ignore_dests") or [])
    allow = set(cfg.get("allow") or [])
    shared = list(cfg.get("shared_readers") or [])
    readers_map = cfg.get("command_readers") or {}
    readers = list(readers_map.get(command) or []) + shared
    assert readers, f"no command_readers for {command} in pyproject"

    dests = _subparser_dests(build_parser()).get(command, set())
    src = _read_bundle(readers)
    dead = sorted(
        d
        for d in dests
        if d not in ignore and d not in allow and not _dest_mentioned(src, d)
    )
    assert not dead, (
        f"dead CLI dests on `{command}` (declared but never read in readers):\n"
        + "\n".join(f"  - {d}" for d in dead)
        + "\nAdd a reader, remove the flag, or allowlist in "
        "[tool.blockchecks.dead_flags]."
    )


def test_helper_bleed_quic_timeout_not_on_scan_pair() -> None:
    from blockchecks.cli.parser import build_parser

    dests = _subparser_dests(build_parser())
    assert "quic_timeout" not in dests.get("scan", set())
    assert "quic_timeout" not in dests.get("pair", set())
    assert "quic_timeout" not in dests.get("tcp", set())


def test_helper_bleed_preflight_not_on_tcp() -> None:
    from blockchecks.cli.parser import build_parser

    dests = _subparser_dests(build_parser()).get("tcp", set())
    for d in (
        "skip_ip_block",
        "prolog_content",
        "abort_on_nfqws2",
        "force",
        "skip_prolog",
        "unblocked_dom",
    ):
        assert d not in dests, f"tcp must not expose preflight dest {d}"


def test_pair_has_no_orphan_ns() -> None:
    from blockchecks.cli.parser import build_parser

    assert "ns" not in _subparser_dests(build_parser()).get("pair", set())


def test_parity_dests_full_vs_pair() -> None:
    """Critical dests present on both full (main) and pair (parser) via shared helpers."""
    from blockchecks.cli.parser import build_parser
    from blockchecks.main import build_arg_parser

    cfg = tool_section("tool", "blockchecks", "dead_flags")
    parity = list(cfg.get("parity_dests") or [])
    assert parity

    pair_dests = _subparser_dests(build_parser()).get("pair", set())
    full = build_arg_parser()
    full_dests = {a.dest for a in full._actions if a.dest}

    missing_pair = [d for d in parity if d not in pair_dests]
    missing_full = [d for d in parity if d not in full_dests]
    assert not missing_pair, f"parity dests missing on pair: {missing_pair}"
    assert not missing_full, f"parity dests missing on full: {missing_full}"

    # Shared helpers are the single source for DNS/preflight/repeats
    import inspect

    from blockchecks import main as main_mod

    src = inspect.getsource(main_mod.build_arg_parser)
    assert "add_secure_dns_args" in src
    assert "add_curl_repeats_args" in src
    assert "add_domain_filter_args" in src
    assert 'g.add_argument("--no-secure-dns"' not in src


def test_scan_no_suppress_udp_aliases() -> None:
    from blockchecks.cli.parser import build_parser

    scan = _subparser_dests(build_parser()).get("scan", set())
    for d in ("full_voice", "udp_bypass", "auto_discover", "udp_timeout"):
        assert d not in scan, f"scan must not expose suppressed pair alias {d}"
