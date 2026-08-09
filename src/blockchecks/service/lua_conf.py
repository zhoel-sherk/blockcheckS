"""Bridge conf generation — flat nfqws2 conf with scan_pick batch strategies."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

from blockchecks.engine.blob_aliases import append_blob_cli_lines, extract_blob_names
from blockchecks.engine.config import (
    BLOB_DIR,
    NFQUEUE_TCP,
    get_blockchecks_lua_scripts,
    get_lua_init_scripts,
)


def stage_blockchecks_lua(ipc_dir: Path, extra: list[str] | None = None) -> list[Path]:
    """Copy bridge Lua into WRITABLE tree (nfqws2 drops privs; repo paths may be unreadable)."""
    lua_dir = ipc_dir / "lua"
    lua_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(lua_dir, 0o755)
    staged: list[Path] = []
    for src in get_blockchecks_lua_scripts(extra):
        dst = lua_dir / src.name
        shutil.copy2(src, dst)
        os.chmod(dst, 0o644)
        staged.append(dst)
    return staged


def blockchecks_lua_init_lines(extra: list[str] | None = None) -> list[str]:
    """--lua-init lines for blockchecks bridge scripts (after zapret trio)."""
    lines: list[str] = []
    for path in get_blockchecks_lua_scripts(extra):
        if path.is_file():
            lines.append(f"--lua-init=@{path}")
    return lines


def _strategy_filter_lines(protocol: str) -> list[str]:
    if protocol == "http":
        return [
            f"--qnum={NFQUEUE_TCP}",
            "--filter-tcp=80",
            "--filter-l3=ipv4",
            "--filter-l7=http",
            "--ipcache-lifetime=0",
            "--bind-fix4",
            "--payload=http_req",
        ]
    return [
        f"--qnum={NFQUEUE_TCP}",
        "--filter-tcp=443",
        "--filter-l3=ipv4",
        "--filter-l7=tls",
        "--ipcache-lifetime=0",
        "--bind-fix4",
        "--payload=tls_client_hello",
    ]


def _split_cli_args(raw_line: str) -> list[str]:
    out: list[str] = []
    for arg in raw_line.split(" --"):
        arg = arg.strip()
        if not arg:
            continue
        if not arg.startswith("--"):
            arg = "--" + arg
        out.append(arg)
    return out


def _append_strategy_desyncs(lines: list[str], strategy: str, strategy_n: int) -> None:
    tag = f":strategy={strategy_n}"
    for raw_line in strategy.split("\n"):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        if raw_line.startswith("--"):
            for cli in _split_cli_args(raw_line):
                lines.append(cli)
        else:
            desync = raw_line if ":strategy=" in raw_line else raw_line + tag
            lines.append(f"--lua-desync={desync}")


def build_bridge_conf(
    strategies: list[str],
    ipc_dir: Path,
    *,
    protocol: str = "tls12",
    extra_lua_init: list[str] | None = None,
) -> str:
    """Build nfqws2 flat conf: writable + scan_pick batch with strategy=1..N."""
    lines: list[str] = [
        f"--writable={ipc_dir}",
        f"--qnum={NFQUEUE_TCP}",
    ]
    for lua in get_lua_init_scripts():
        if os.path.isfile(lua):
            lines.append(f"--lua-init=@{lua}")
    for path in stage_blockchecks_lua(ipc_dir, extra_lua_init):
        lines.append(f"--lua-init=@{path}")
    lines.extend(_strategy_filter_lines(protocol))
    lines.append("--lua-desync=bs_poll_strategy")
    lines.append("--lua-desync=smart_fallback")
    lines.append("--lua-desync=scan_pick")

    all_blob_names: list[str] = []
    for strat in strategies:
        all_blob_names.extend(extract_blob_names(strat))
    append_blob_cli_lines(lines, all_blob_names, BLOB_DIR)

    for i, strat in enumerate(strategies, start=1):
        _append_strategy_desyncs(lines, strat, i)

    return "\n".join(lines) + "\n"


def write_bridge_conf(
    strategies: list[str],
    ipc_dir: Path,
    *,
    protocol: str = "tls12",
    extra_lua_init: list[str] | None = None,
    tag: str = "bridge",
) -> str:
    """Write bridge conf to a temp file; return path."""
    text = build_bridge_conf(
        strategies, ipc_dir, protocol=protocol, extra_lua_init=extra_lua_init
    )
    fd, path = tempfile.mkstemp(prefix=f"bs_{tag}_", suffix=".conf")
    os.close(fd)
    Path(path).write_text(text, encoding="utf-8")
    return path
