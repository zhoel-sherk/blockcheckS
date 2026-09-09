"""Flat nfqws2 conf for a lua-bridge batch (scan_pick). CLI parse/escape is in conf_builder."""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from pathlib import Path

from blockchecks.engine.blob_aliases import (
    append_blob_cli_lines,
    apply_blob_renames,
    extract_blob_names,
)
from blockchecks.engine.conf_builder import (
    build_filter_lines,
    escape_conf_lt,
    sanitize_arg_for_conf,
    split_cli_args,
)
from blockchecks.engine.config import (
    BLOB_DIR,
    get_blockchecks_lua_scripts,
    get_lua_init_scripts,
)

log = logging.getLogger(__name__)

import blockchecks.engine.config as _cfg_mod  # noqa: E402


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


def _append_strategy_desyncs(lines: list[str], strategy: str, strategy_n: int) -> None:
    tag = f":strategy={strategy_n}"
    for raw_line in strategy.split("\n"):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        if raw_line.startswith("--"):
            for cli in split_cli_args(raw_line):
                lines.append(sanitize_arg_for_conf(cli))
        else:
            desync = raw_line if ":strategy=" in raw_line else raw_line + tag
            lines.append(f"--lua-desync={escape_conf_lt(desync)}")


def build_bridge_conf(
    strategies: list[str],
    ipc_dir: Path,
    *,
    protocol: str = "tls12",
    extra_lua_init: list[str] | None = None,
) -> str:
    """Build nfqws2 flat conf: writable + scan_pick batch with strategy=1..N.

    Mode A (``BRIDGE_MODE == "A"``, AUDIT §20): the conf carries ONLY the
    orchestrators — the full strategy line is published per-probe via
    strategy.cmd and parsed in Lua. Blob declarations cover the WHOLE catalog
    (a Mode A cmd may reference any blob, not just this batch's).
    """
    mode_a = bool(getattr(_cfg_mod, "BRIDGE_MODE", "B") == "A")
    lines: list[str] = [
        f"--writable={ipc_dir}",
    ]
    for lua in get_lua_init_scripts():
        if os.path.isfile(lua):
            lines.append(f"--lua-init=@{lua}")
    for path in stage_blockchecks_lua(ipc_dir, extra_lua_init):
        lines.append(f"--lua-init=@{path}")
    lines.extend(build_filter_lines(protocol))
    lines.append("--lua-desync=bs_poll_strategy")
    lines.append("--lua-desync=smart_fallback")
    lines.append("--lua-desync=scan_pick")

    if mode_a:
        # Full catalog: every file blob + every alias name (google/max_ru/4pda
        # resolve through BLOB_ALIAS_MAP, not the dir listing — a Mode A cmd
        # may reference ANY blob) + built-ins (always resolvable by nfqws2).
        from blockchecks.engine.blob_aliases import BLOB_ALIAS_MAP

        all_blob_names = sorted(
            p.stem for p in Path(BLOB_DIR).glob("*.bin")
        ) if Path(BLOB_DIR).is_dir() else []
        all_blob_names += list(BLOB_ALIAS_MAP.keys())
        all_blob_names += ["fake_default_tls", "fake_default_http", "fake_default_quic"]
        renames = append_blob_cli_lines(lines, sorted(set(all_blob_names)), BLOB_DIR)
        unresolvable = sorted(n for n, safe in renames.items() if not safe)
        if unresolvable:
            log.warning(
                "%s",
                f"  WARNING: bridge conf (mode A) has unresolvable blobs {unresolvable} "
                "— strategies referencing them fail per-packet",
            )
    else:
        all_blob_names = []
        for strat in strategies:
            all_blob_names.extend(extract_blob_names(strat))
        renames = append_blob_cli_lines(lines, all_blob_names, BLOB_DIR)
    unresolvable = sorted(n for n, safe in renames.items() if not safe)
    if unresolvable:
        log.warning(
            "%s",
            f"  WARNING: bridge conf has unresolvable blobs {unresolvable} — "
            f"affected strategies will fail per-packet (no APPLIED, clean traffic)",
        )
    if any(k != v for k, v in renames.items()):
        log.info(
            "%s",
            f"  [bridge] blob identifiers renamed for nfqws2: "
            f"{ {k: v for k, v in renames.items() if k != v and v} }",
        )

    if not mode_a:
        for i, strat in enumerate(strategies, start=1):
            _append_strategy_desyncs(lines, apply_blob_renames(strat, renames), i)

    return "\n".join(lines) + "\n"


def write_bridge_conf(
    strategies: list[str],
    ipc_dir: Path,
    *,
    protocol: str = "tls12",
    extra_lua_init: list[str] | None = None,
    tag: str = "bridge",
    host_qnum: int = 0,
) -> str:
    """Write bridge conf to a temp file; return path.

    ``host_qnum`` > 0 rewrites the conf for a host-mode slot (docs/hostmode.md
    §6): ``--qnum`` override + mandatory ``--fwmark`` anti-loop +
    ``--filter-mark`` second lock via the tested ``hostify_conf_text``.
    """
    text = build_bridge_conf(strategies, ipc_dir, protocol=protocol, extra_lua_init=extra_lua_init)
    if host_qnum:
        from blockchecks.engine.config import DESYNC_MARK, PROBE_MARK
        from blockchecks.service.host_isol import hostify_conf_text

        text = hostify_conf_text(
            text, qnum=host_qnum, desync_mark=DESYNC_MARK, probe_mark=PROBE_MARK
        )
    fd, path = tempfile.mkstemp(prefix=f"bs_{tag}_", suffix=".conf")
    os.close(fd)
    Path(path).write_text(text, encoding="utf-8")
    return path
