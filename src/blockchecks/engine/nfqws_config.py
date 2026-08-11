"""nfqws2 config building helpers (split out of async_runner god-file, day-5).

Pure config-string builders: no network/worker state. Used both by the
in-namespace workers and by ``bs tcp`` sync path.
"""

from __future__ import annotations

import os
import subprocess as sp

from blockchecks.engine.config import (
    BLOB_DIR,
    NFQUEUE_TCP,
    NFQUEUE_UDP,
    get_lua_init_scripts,
)


def _sudo(*args: str) -> str:
    r = sp.run(["sudo"] + list(args), capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        raise RuntimeError(f"sudo {' '.join(args)}: {r.stderr[:200]}")
    return r.stdout.strip()


def _add_blobs_from_strategy(lines: list[str], strategy: str) -> None:
    """Parse strategy for blob=NAME and seqovl_pattern=NAME; add --blob lines."""
    from blockchecks.engine.blob_aliases import append_blob_cli_lines, extract_blob_names

    append_blob_cli_lines(lines, extract_blob_names(strategy), BLOB_DIR)


def _split_cli_args(raw_line: str) -> list[str]:
    """Split a line of nfqws2 CLI args on ' --' boundaries."""
    out = []
    for arg in raw_line.split(" --"):
        arg = arg.strip()
        if not arg:
            continue
        if not arg.startswith("--"):
            arg = "--" + arg
        out.append(arg)
    return out


def _build_inline_nfqws_lines(
    strategy: str, protocol: str, extra_lua_desync: str = ""
) -> list[str]:
    """Build nfqws2 config lines for inline lua-desync strategy."""
    is_http = protocol == "http"
    if is_http:
        config_lines = [
            f"--qnum={NFQUEUE_TCP}",
            "--filter-tcp=80",
            "--filter-l3=ipv4",
            "--filter-l7=http",
            "--ipcache-lifetime=0",
            "--bind-fix4",
            "--payload=http_req",
        ]
    else:
        config_lines = [
            f"--qnum={NFQUEUE_TCP}",
            "--filter-tcp=443",
            "--filter-l3=ipv4",
            "--filter-l7=tls",
            "--ipcache-lifetime=0",
            "--bind-fix4",
            "--payload=tls_client_hello",
        ]
    for lua in get_lua_init_scripts():
        if os.path.exists(lua):
            config_lines.append(f"--lua-init=@{lua}")
    _add_blobs_from_strategy(config_lines, strategy)
    for raw_line in strategy.split("\n"):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        if raw_line.startswith("--"):
            config_lines.extend(_split_cli_args(raw_line))
        else:
            config_lines.append(f"--lua-desync={raw_line}")
    if extra_lua_desync:
        config_lines.append(f"--lua-desync={extra_lua_desync}")
    return config_lines


def _build_quic_nfqws_lines(strategy: str) -> list[str]:
    """Build nfqws2 config for HTTP/3 QUIC strategies (UDP/443, BC2-10)."""
    if strategy.strip().startswith("--"):
        config_lines = [
            f"--qnum={NFQUEUE_UDP}",
            "--filter-l3=ipv4",
            "--ipcache-lifetime=0",
            "--bind-fix4",
        ]
        for lua in get_lua_init_scripts():
            if os.path.exists(lua):
                config_lines.append(f"--lua-init=@{lua}")
        for raw_line in strategy.split("\n"):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            config_lines.extend(_split_cli_args(raw_line))
        return config_lines

    config_lines = [
        f"--qnum={NFQUEUE_UDP}",
        "--filter-udp=443",
        "--filter-l3=ipv4",
        "--filter-l7=quic",
        "--ipcache-lifetime=0",
        "--bind-fix4",
        "--payload=quic_initial",
    ]
    for lua in get_lua_init_scripts():
        if os.path.exists(lua):
            config_lines.append(f"--lua-init=@{lua}")
    _add_blobs_from_strategy(config_lines, strategy)
    for raw_line in strategy.split("\n"):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        if raw_line.startswith("--"):
            config_lines.extend(_split_cli_args(raw_line))
        else:
            config_lines.append(f"--lua-desync={raw_line}")
    return config_lines
