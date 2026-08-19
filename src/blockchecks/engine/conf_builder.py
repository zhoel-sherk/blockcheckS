"""Build nfqws2 config text: keenetic shell-env, raw flat conf, CLI sanitization.

Single source for nfqws2 CLI arg parsing / escaping shared by ``nfqws_config``
(in-namespace + sync workers) and ``service.lua_conf`` (bridge backend). The two
formerly kept duplicate ``_split_cli_args`` and only ``lua_conf`` had the ``<``
escape — that asymmetry is fixed here.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from blockchecks.engine.blob_aliases import (
    STOCK_KEENETIC_BLOB_FILES,
    append_blob_cli_lines,
    blob_cli_lines,
    blob_export_cli_line,
    blob_export_filename,
    extract_blob_names,
    resolve_blob_path,
)
from blockchecks.engine.config import (
    BLOB_DIR,
    LUA_CUSTOM_DIR,
    NFQUEUE_TCP,
    NFQUEUE_UDP,
    get_lua_init_scripts,
)

log = logging.getLogger(__name__)

# Keenetic Entware layout (override via prefix=)
DEFAULT_KEENETIC_PREFIX = "/opt/etc/nfqws2"

CIRCULAR_TCP = "circular:fails=2:time=300:retrans=3:nld=2"
CIRCULAR_UDP = "circular:fails=2:time=300:retrans=3:nld=2"

DEFAULT_UDP_FILTER = "590-600,1400,3478-3481,5349,19294-19344,49152-65535"
DEFAULT_UDP_PORTS = "443,590:600,1400,3478:3481,5349,19294:19344,49152:65535"
STOCK_LUA_NAMES = ("zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua")
_STRATEGY_N_RE = re.compile(r":strategy=\d+\s*$")
_LUA_FN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
DEFAULT_UDP_L7 = "wireguard,stun,discord,mtproto,unknown"
DEFAULT_UDP_PAYLOAD = (
    "wireguard_initiation,wireguard_response,wireguard_cookie,"
    "stun,discord_ip_discovery,mtproto_initial,unknown"
)

# Custom Lua functions that must live on the target host (not in stock
# zapret-lib / zapret-auto). Registered in lua/custom/manifest.toml with
# included/excluded params. Export emits a deploy comment pointing at the
# file in this repo.

_CUSTOM_LUA_MANIFEST: dict[str, dict[str, Any]] | None = None


def load_custom_lua_manifest() -> dict[str, dict[str, Any]]:
    """Load lua/custom/manifest.toml → {fn: {file, included, excluded}}.

    Cached. Falls back to an empty dict on any read/parse error (never raises).
    """
    global _CUSTOM_LUA_MANIFEST
    if _CUSTOM_LUA_MANIFEST is not None:
        return _CUSTOM_LUA_MANIFEST
    import tomllib

    from blockchecks.engine.config import LUA_CUSTOM_DIR

    manifest_path = os.path.join(LUA_CUSTOM_DIR, "manifest.toml")
    registry: dict[str, dict[str, Any]] = {}
    try:
        with open(manifest_path, "rb") as f:
            data = tomllib.load(f)
        for entry in data.get("lua", []):
            name = str(entry.get("name") or "").lower()
            if not name:
                continue
            registry[name] = {
                "file": str(entry.get("file") or f"{name}.lua"),
                "included": list(entry.get("included") or []),
                "excluded": list(entry.get("excluded") or []),
                "description": str(entry.get("description") or ""),
            }
    except (OSError, tomllib.TOMLDecodeError, TypeError, ValueError):
        pass
    _CUSTOM_LUA_MANIFEST = registry
    return registry


def custom_lua_comment(strategy: str, prefix: str = DEFAULT_KEENETIC_PREFIX) -> str | None:
    """COPY comment for a custom Lua function, or None.

    ``# COPY lua: <abs source> -> {prefix}/lua/<file>``
    """
    comments = custom_lua_copy_comments(strategy, prefix)
    return comments[0] if comments else None


def _abs_or_str(p: Path) -> str:
    try:
        return str(p.resolve())
    except OSError:
        return str(p)


def custom_lua_copy_comments(strategy: str, prefix: str = DEFAULT_KEENETIC_PREFIX) -> list[str]:
    """COPY comments for every custom Lua function used in *strategy*."""
    low = strategy.lower()
    return [
        f"# COPY lua: {_abs_or_str(Path(LUA_CUSTOM_DIR) / str(meta['file']))}"
        f" -> {prefix}/lua/{meta['file']}"
        for fn, meta in load_custom_lua_manifest().items()
        if re.search(rf"(?:^|:|=){re.escape(fn)}:", low)
    ]


def custom_lua_files_for(*strategies: str) -> list[str]:
    """Unique custom lua filenames referenced by *strategies* (manifest order)."""
    blob = "\n".join(strategies).lower()
    return list(
        dict.fromkeys(
            str(meta["file"])
            for fn, meta in load_custom_lua_manifest().items()
            if re.search(rf"(?:^|:|=){re.escape(fn)}:", blob)
        )
    )


def looks_like_conf_path(text: str) -> bool:
    """True when *text* is a filesystem .conf path (optional :strategy=N suffix)."""
    head = _STRATEGY_N_RE.sub("", text.strip())
    return head.endswith(".conf") and ("/" in head or os.path.sep in head)


def is_lua_function_core(text: str) -> bool:
    """True when *text* is a lua-desync core (function name, not a path)."""
    if not text or text.startswith(("/", "--")):
        return False
    first = text.split(":", 1)[0].strip()
    return bool(_LUA_FN_RE.match(first))


def lua_desync_cores_from_conf(path: str) -> list[str]:
    """Extract ``--lua-desync=`` cores from a .conf file; skip path-like values."""
    conf = Path(_STRATEGY_N_RE.sub("", path.strip()))
    try:
        lines = conf.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        log.warning("export: cannot read strategy conf %s: %s", conf, e)
        return []
    cores = [
        raw[len("--lua-desync=") :].strip()
        for raw in (ln.strip() for ln in lines)
        if raw.startswith("--lua-desync=")
    ]
    return [c for c in cores if is_lua_function_core(c)]


def _export_part(part: str) -> list[str]:
    if looks_like_conf_path(part):
        return lua_desync_cores_from_conf(part)
    if part.startswith("--lua-desync="):
        core = part[len("--lua-desync=") :].strip()
        return [core] if is_lua_function_core(core) else []
    if part.startswith("--"):
        cores = [
            tok[len("--lua-desync=") :]
            for tok in split_cli_args(part)
            if tok.startswith("--lua-desync=")
            and is_lua_function_core(tok[len("--lua-desync=") :])
        ]
        if cores:
            return cores
        if "/" in part:
            log.warning("export: skip path-bearing CLI fragment %r", part[:80])
            return []
        return [part]
    if is_lua_function_core(part):
        return [part]
    log.warning("export: skip non-function strategy %r", part[:80])
    return []


def strategy_parts_for_export(strat: str) -> list[str]:
    """Cores / CLI fragments for export; never returns a .conf filesystem path."""
    text = strat.strip()
    if not text:
        return []
    if looks_like_conf_path(text):
        return lua_desync_cores_from_conf(text)
    return [
        p
        for raw in text.split("\n")
        if (part := raw.strip())
        for p in _export_part(part)
    ]


def flatten_export_strategies(strategies: list[str]) -> list[str]:
    """Function cores only (no ``--`` CLI fragments)."""
    return [
        p
        for s in strategies
        for p in strategy_parts_for_export(s)
        if not p.startswith("--")
    ]


_TTL_PARAM_RE = re.compile(r"(?:^|:)(?:ip_ttl|ip6_ttl)=(-?\d+)(?:(?::)|$)")


def core_ttl_ok(core: str) -> bool:
    """False when any ``ip_ttl`` / ``ip6_ttl`` is outside 0–255."""
    return all(0 <= int(m.group(1)) <= 255 for m in _TTL_PARAM_RE.finditer(core))


def filter_export_strategies(strategies: list[str]) -> list[str]:
    """Drop unreadable / path-only rows and cores with TTL outside 0–255."""
    return [s for s in strategies if _keep_export_strategy(s)]


def _keep_export_strategy(strat: str) -> bool:
    parts = strategy_parts_for_export(strat)
    if not parts:
        return False
    cores = [p for p in parts if not p.startswith("--")]
    if any(not core_ttl_ok(c) for c in cores):
        log.warning("export: skip strategy with ip_ttl/ip6_ttl outside 0-255: %r", strat[:80])
        return False
    blobs = extract_blob_names(*cores)
    bad = [n for n in blobs if not _LUA_FN_RE.match(n)]
    if bad:
        log.warning("export: skip strategy with non-lua blob name %s: %r", bad, strat[:80])
        return False
    return True


def desync_cli_lines(strategies: list[str]) -> list[str]:
    """``--lua-desync=fn:…`` or pass-through ``--`` fragments; never a .conf path."""
    return [
        part if part.startswith("--") else f"--lua-desync={_ensure_strategy_n(part, i)}"
        for i, strat in enumerate(strategies, start=1)
        for part in strategy_parts_for_export(strat)
    ]


def blob_copy_comment(name: str, prefix: str) -> str | None:
    """COPY comment for a non-stock blob, or None."""
    fname = blob_export_filename(name)
    if not fname or fname in STOCK_KEENETIC_BLOB_FILES:
        return None
    src = resolve_blob_path(name)
    dest = f"{prefix}/blobs/{fname}"
    return f"# COPY blob: {src} -> {dest}" if src else f"# COPY blob: <missing {name}> -> {dest}"


def ipset_export_path(prefix: str) -> str:
    return f"{prefix}/lists/user.ipset"


def blob_copy_comments(names: list[str], prefix: str) -> list[str]:
    return list(dict.fromkeys(c for n in names if (c := blob_copy_comment(n, prefix))))


def _export_blob_names(*groups: list[str]) -> list[str]:
    cores = flatten_export_strategies([s for g in groups for s in g])
    return extract_blob_names(*cores)


def _strategy_params(strategy: str) -> dict[str, str]:
    """Parse ``key=value`` params from a strategy core (multiline-aware)."""
    params: dict[str, str] = {}
    for part in strategy.split("\\n"):
        for m in re.finditer(r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)=([^:\s]+)", part):
            key, val = m.group(1), m.group(2)
            if key not in params:
                params[key] = val
    return params


def validate_custom_lua_params(strategy: str) -> list[str]:
    """Return issues for a strategy using a custom Lua function.

    Checks the custom function's manifest params: an *excluded* param present in
    the strategy is a conflict (error), a param neither included nor excluded is
    undocumented (warning). Returns a list of human-readable messages, empty if
    no custom function is used or all params are allowed.
    """
    low = strategy.lower()
    for fn, meta in load_custom_lua_manifest().items():
        if not re.search(rf"(?:^|:|=){re.escape(fn)}:", low):
            continue
        params = _strategy_params(strategy)
        included = set(meta.get("included") or [])
        excluded = set(meta.get("excluded") or [])
        issues: list[str] = []
        for key in params:
            if key in excluded:
                issues.append(
                    f"{fn}: param '{key}' is excluded (custom Lua {meta['file']} "
                    f"does not support it)"
                )
            elif key not in included and key not in ("optional",):
                issues.append(
                    f"{fn}: param '{key}' undocumented for {meta['file']} "
                    f"(add to included/excluded in lua/custom/manifest.toml)"
                )
        return issues
    return []


def split_cli_args(raw_line: str) -> list[str]:
    """Split a line of nfqws2 CLI args on `` --`` boundaries.

    A strategy line like ``--filter-tcp=443 --payload=tls_client_hello`` is
    split into distinct nfqws2 CLI flags for @file confs.
    """
    out = []
    for arg in raw_line.split(" --"):
        arg = arg.strip()
        if not arg:
            continue
        if not arg.startswith("--"):
            arg = "--" + arg
        out.append(arg)
    return out


def escape_conf_lt(cli: str) -> str:
    """Escape ``<`` in a CLI arg so nfqws2 can read it from an @conf file.

    nfqws2's conf splitter treats a bare ``<`` (e.g. ``--out-range=s1<d1``) as a
    bad token and fails with "failed to split command line options". Quoting or
    ``\\<`` both work; we use ``\\<`` (plain backslash escape).
    """
    return cli.replace("<", "\\<")


def sanitize_arg_for_conf(cli: str) -> str:
    """Escape a single CLI arg for embedding in an @conf file."""
    return escape_conf_lt(cli)


def add_blobs_from_strategy(lines: list[str], strategy: str) -> None:
    """Parse strategy for blob=NAME and seqovl_pattern=NAME; add --blob lines."""
    append_blob_cli_lines(lines, extract_blob_names(strategy), BLOB_DIR)


def build_filter_lines(protocol: str) -> list[str]:
    """Shared nfqws2 filter/payload lines for a protocol (tls|http|quic)."""
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
    if protocol == "quic":
        return [
            f"--qnum={NFQUEUE_UDP}",
            "--filter-udp=443",
            "--filter-l3=ipv4",
            "--filter-l7=quic",
            "--ipcache-lifetime=0",
            "--bind-fix4",
            "--payload=quic_initial",
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


def _ensure_strategy_n(strategy: str, n: int) -> str:
    """Append :strategy=N if missing."""
    s = strategy.strip()
    if re.search(r":strategy=\d+\b", s):
        return s
    return f"{s}:strategy={n}"


def _hash_comment(text: str) -> str:
    """``#`` line safe for nfqws2 @file (parentheses break its option splitter)."""
    body = text.lstrip("# ").replace("(", "[").replace(")", "]")
    return f"# {body}"


def _quote_multiline(value: str) -> str:
    """Shell double-quoted value; keep newlines with leading space (keenetic style)."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _lua_init_lines(prefix: str, extra: list[str] | None = None) -> list[str]:
    """Always ``{prefix}/lua/…`` — never host-exists fallback to /opt/zapret2."""
    names = (*STOCK_LUA_NAMES, *(extra or []))
    return [f"--lua-init=@{prefix}/lua/{name}" for name in names]


def _keenetic_copy_header(
    tcp: list[str],
    udp: list[str],
    quic: list[str],
    prefix: str,
    ipset_file: str | None,
) -> list[str]:
    cores = flatten_export_strategies(tcp + udp + quic)
    names = _export_blob_names(tcp, udp, quic)
    return [
        f"# Uncommented paths: {prefix}/{{blobs,lua,lists}} only.",
        "# --filter-l7 is the flow protocol; --payload is packet type "
        "(sticky until the next --payload=).",
        *custom_lua_copy_comments("\n".join(cores), prefix),
        *blob_copy_comments(names, prefix),
        *(
            [f"# COPY ipset: {ipset_file} -> {ipset_export_path(prefix)}"]
            if ipset_file
            else []
        ),
    ]


def build_keenetic_conf(
    *,
    tcp_strategies: list[str],
    udp_strategies: list[str],
    quic_strategies: list[str] | None = None,
    isp_interface: str = "eth3",
    prefix: str = DEFAULT_KEENETIC_PREFIX,
    mode: str = "auto",
    domains: list[str] | None = None,
    comment: str = "",
    ipset_ips: list[str] | None = None,
    ipset_file: str | None = None,
) -> str:
    """Keenetic / Entware nfqws2.conf (shell env variables).

    ``ipset_ips`` → emit ``--ipset-ip=<comma list>``; ``ipset_file`` → emit
    ``--ipset=@{prefix}/lists/user.ipset`` plus a ``# COPY ipset:`` comment
    (the host path is never a working argument).
    """
    quic_strategies = filter_export_strategies(
        quic_strategies or ["fake:blob=quic_initial:repeats=11"]
    )
    tcp_strategies = filter_export_strategies(tcp_strategies)
    udp_strategies = filter_export_strategies(udp_strategies)
    extra_lua = custom_lua_files_for(
        *flatten_export_strategies(tcp_strategies + udp_strategies + quic_strategies)
    )
    blob_names = _export_blob_names(tcp_strategies, udp_strategies, quic_strategies)
    blob_parts = [ln for n in blob_names if (ln := blob_export_cli_line(n, prefix))]
    ipset_part = (
        [f"--ipset=@{ipset_export_path(prefix)}"]
        if ipset_file
        else (["--ipset-ip=" + ",".join(ipset_ips)] if ipset_ips else [])
    )
    base_args = "\n ".join(_lua_init_lines(prefix, extra_lua) + blob_parts + ipset_part)

    tcp_desync = desync_cli_lines(tcp_strategies)
    tcp_circular = (
        [
            "--out-range=-s34228",
            f"--in-range=-s5556 --lua-desync={CIRCULAR_TCP}",
            "--in-range=x",
        ]
        if flatten_export_strategies(tcp_strategies)
        else []
    )
    tcp_args = "\n ".join(
        [
            "--filter-tcp=443,80,1984,5222",
            "--filter-l7=http,tls,mtproto",
            "--payload=tls_client_hello,mtproto_initial",
            *tcp_circular,
            *tcp_desync,
            "--payload=http_req",
            "--lua-desync=http_methodeol:badsum",
        ]
    )
    quic_args = "\n ".join(
        [
            "--filter-udp=443",
            "--filter-l7=quic",
            "--payload=quic_initial",
            *desync_cli_lines(quic_strategies),
        ]
    )
    udp_desync = desync_cli_lines(udp_strategies)
    udp_circular = (
        [f"--lua-desync={CIRCULAR_UDP}"]
        if flatten_export_strategies(udp_strategies)
        else []
    )
    udp_args = "\n ".join(
        [
            f"--filter-udp={DEFAULT_UDP_FILTER}",
            f"--filter-l7={DEFAULT_UDP_L7}",
            "--out-range=<n2",
            f"--payload={DEFAULT_UDP_PAYLOAD}",
            *udp_circular,
            *udp_desync,
        ]
    )

    extra = {"auto": "$MODE_AUTO", "list": "$MODE_LIST", "all": "$MODE_ALL"}.get(
        mode.lower(), "$MODE_AUTO"
    )

    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    hdr = [
        f"# Generated by blockcheckS nfconf at {ts}",
        *([f"# {comment}"] if comment else []),
        *_keenetic_copy_header(
            tcp_strategies, udp_strategies, quic_strategies, prefix, ipset_file
        ),
        *(
            [
                f"# domains ({len(domains)}): "
                + ",".join(domains[:8])
                + ("..." if len(domains) > 8 else "")
            ]
            if domains
            else []
        ),
        "# Format: nfqws2-keenetic etc/nfqws2/nfqws2.conf",
        "",
    ]

    body = f"""# Provider network interface
ISP_INTERFACE={_quote_multiline(isp_interface)}

# Startup arguments
NFQWS_BASE_ARGS={_quote_multiline(base_args)}

# HTTP(S) strategy
NFQWS_ARGS={_quote_multiline(tcp_args)}

# QUIC strategy
NFQWS_ARGS_QUIC={_quote_multiline(quic_args)}

# UDP strategy (doesn't use lists from NFQWS_EXTRA_ARGS)
NFQWS_ARGS_UDP={_quote_multiline(udp_args)}

# $MODE_AUTO / $MODE_LIST / $MODE_ALL — defined by keenetic init scripts
NFQWS_EXTRA_ARGS="{extra}"

# UDP ports for iptables rules
UDP_PORTS={DEFAULT_UDP_PORTS}
"""
    return "\n".join(hdr) + body


def build_raw_conf(
    *,
    tcp_strategies: list[str],
    udp_strategies: list[str],
    quic_strategies: list[str] | None = None,
    blobs_dir: str = BLOB_DIR,
    qnum_tcp: int = 200,
    comment: str = "",
    domains: list[str] | None = None,
    ipset_ips: list[str] | None = None,
    ipset_file: str | None = None,
) -> str:
    """Flat nfqws2 @file conf for the **scan host** (abs lua/blob paths).

    Keenetic/router export uses ``build_keenetic_conf`` (prefix-only paths).
    dpi-tester consumes this raw ``@file`` (absolute ``/opt/zapret2`` lua and host blobs).
    ``ipset_ips`` → ``--ipset-ip=``; ``ipset_file`` → ``--ipset=@<host path>``.
    """
    tcp_strategies = filter_export_strategies(tcp_strategies)
    udp_strategies = filter_export_strategies(udp_strategies)
    quic_strategies = filter_export_strategies(quic_strategies or [])
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    cores = flatten_export_strategies(tcp_strategies + udp_strategies + quic_strategies)
    extra_lua = custom_lua_files_for(*cores)
    lua_inits = [f"--lua-init=@{p}" for p in get_lua_init_scripts() if os.path.exists(p)]
    lua_inits += [
        f"--lua-init=@{Path(LUA_CUSTOM_DIR) / fname}"
        for fname in extra_lua
        if (Path(LUA_CUSTOM_DIR) / fname).is_file()
    ]
    blob_names = extract_blob_names(*cores)
    ipset_lines = (
        [f"--ipset=@{ipset_file}"]
        if ipset_file
        else (["--ipset-ip=" + ",".join(ipset_ips)] if ipset_ips else [])
    )
    lines = [
        _hash_comment(f"blockcheckS raw nfqws2 conf host-oriented {ts}"),
        *([_hash_comment(comment)] if comment else []),
        *custom_lua_copy_comments("\n".join(cores)),
        f"--qnum={qnum_tcp}",
        "--ipcache-lifetime=0",
        "--bind-fix4",
        *lua_inits,
        *blob_cli_lines(blob_names, blobs_dir),
        *ipset_lines,
        *(["--hostlist-domains=" + ",".join(domains)] if domains else []),
        "--filter-tcp=443",
        "--filter-l3=ipv4",
        "--filter-l7=tls",
        "--payload=tls_client_hello",
        *desync_cli_lines(tcp_strategies),
    ]
    if quic_strategies:
        lines += [
            "--new=quic",
            "--filter-udp=443",
            "--filter-l7=quic",
            "--payload=quic_initial",
            *desync_cli_lines(quic_strategies),
        ]
    if udp_strategies:
        lines += [
            "--new=voice",
            "--filter-udp=50000-50100",
            "--filter-l3=ipv4",
            "--filter-l7=discord,stun",
            "--payload=discord_ip_discovery,stun,unknown",
            *desync_cli_lines(udp_strategies),
        ]
    return "\n".join(lines) + "\n"


def write_user_list(path: str, domains: list[str]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for d in domains:
            d = d.strip()
            if d and not d.startswith("#"):
                f.write(d + "\n")


def write_export_bundle(
    conf_text: str,
    out_dir: str | Path,
    *,
    tcp_strats: list[str] | None = None,
    udp_strats: list[str] | None = None,
    quic_strats: list[str] | None = None,
    ipset_file: str | None = None,
    conf_name: str = "nfqws2.conf",
) -> Path:
    """Write *conf_text* plus custom blobs/lua (and optional ipset) under *out_dir*."""
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    conf_path = dest / conf_name
    conf_path.write_text(conf_text, encoding="utf-8")
    cores = flatten_export_strategies(
        (tcp_strats or []) + (udp_strats or []) + (quic_strats or [])
    )
    blob_dir = dest / "blobs"
    for name in extract_blob_names(*cores):
        fname = blob_export_filename(name)
        if not fname or fname in STOCK_KEENETIC_BLOB_FILES:
            continue
        src = resolve_blob_path(name)
        if src and Path(src).is_file():
            blob_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, blob_dir / fname)
    lua_dir = dest / "lua"
    for fname in custom_lua_files_for(*cores):
        src = Path(LUA_CUSTOM_DIR) / fname
        if src.is_file():
            lua_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, lua_dir / fname)
    if ipset_file and Path(ipset_file).is_file():
        lists = dest / "lists"
        lists.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ipset_file, lists / "user.ipset")
    return conf_path
