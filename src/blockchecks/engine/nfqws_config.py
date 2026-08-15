"""nfqws2 config building helpers (split out of async_runner god-file, day-5).

Pure config-string builders: no network/worker state. Used both by the
in-namespace workers and by ``bs tcp`` sync path. Shared CLI arg parsing /
escaping lives in ``blockchecks.engine.conf_builder`` (single source — the
``<`` escape used to exist only in ``service.lua_conf``, causing sync-mode
nfqws2 to crash on ``--out-range=s1<d1`` strategies).
"""

from __future__ import annotations

import os

from blockchecks.engine.conf_builder import (
    add_blobs_from_strategy,
    build_filter_lines,
    sanitize_arg_for_conf,
    split_cli_args,
)
from blockchecks.engine.config import NFQUEUE_UDP, get_lua_init_scripts


def _sudo(*args: str) -> str:
    import subprocess as sp

    r = sp.run(["sudo"] + list(args), capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        raise RuntimeError(f"sudo {' '.join(args)}: {r.stderr[:200]}")
    return r.stdout.strip()


def _build_inline_nfqws_lines(
    strategy: str, protocol: str, extra_lua_desync: str = ""
) -> list[str]:
    """Build nfqws2 config lines for inline lua-desync strategy."""
    config_lines = build_filter_lines(protocol)
    for lua in get_lua_init_scripts():
        if os.path.exists(lua):
            config_lines.append(f"--lua-init=@{lua}")
    add_blobs_from_strategy(config_lines, strategy)
    for raw_line in strategy.split("\n"):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        if raw_line.startswith("--"):
            config_lines.extend(sanitize_arg_for_conf(a) for a in split_cli_args(raw_line))
        else:
            config_lines.append(f"--lua-desync={sanitize_arg_for_conf(raw_line)}")
    if extra_lua_desync:
        config_lines.append(f"--lua-desync={sanitize_arg_for_conf(extra_lua_desync)}")
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
            config_lines.extend(sanitize_arg_for_conf(a) for a in split_cli_args(raw_line))
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
    add_blobs_from_strategy(config_lines, strategy)
    for raw_line in strategy.split("\n"):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        if raw_line.startswith("--"):
            config_lines.extend(sanitize_arg_for_conf(a) for a in split_cli_args(raw_line))
        else:
            config_lines.append(f"--lua-desync={sanitize_arg_for_conf(raw_line)}")
    return config_lines
