"""Build nfqws2 config text: keenetic shell-env, raw flat conf, CLI sanitization.

Single source for nfqws2 CLI arg parsing / escaping shared by ``nfqws_config``
(in-namespace + sync workers) and ``service.lua_conf`` (bridge backend). The two
formerly kept duplicate ``_split_cli_args`` and only ``lua_conf`` had the ``<``
escape — that asymmetry is fixed here.
"""

from __future__ import annotations

import os
import re
import time

from blockchecks.engine.blob_aliases import (
    append_blob_cli_lines,
    blob_cli_lines,
    extract_blob_names,
)
from blockchecks.engine.config import (
    BLOB_DIR,
    NFQUEUE_TCP,
    NFQUEUE_UDP,
    get_lua_init_scripts,
)

# Keenetic Entware layout (override via prefix=)
DEFAULT_KEENETIC_PREFIX = "/opt/etc/nfqws2"

CIRCULAR_TCP = "circular:fails=2:time=300:retrans=3:nld=2"
CIRCULAR_UDP = "circular:fails=2:time=300:retrans=3:nld=2"

DEFAULT_UDP_FILTER = "590-600,1400,3478-3481,5349,19294-19344,50000-65535"
DEFAULT_UDP_PORTS = "443,590:600,1400,3478:3481,5349,19294:19344,50000:65535"
DEFAULT_UDP_L7 = "wireguard,stun,discord,mtproto,unknown"
DEFAULT_UDP_PAYLOAD = (
    "wireguard_initiation,wireguard_response,wireguard_cookie,"
    "stun,discord_ip_discovery,mtproto_initial,unknown"
)


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


def _quote_multiline(value: str) -> str:
    """Shell double-quoted value; keep newlines with leading space (keenetic style)."""
    # Escape backslash and double-quote for shell
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _lua_init_lines(prefix: str) -> list[str]:
    lua_dir = os.path.join(prefix, "lua")
    names = ("zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua")
    lines = []
    for name in names:
        path = os.path.join(lua_dir, name)
        # Fall back to zapret2 paths if keenetic tree missing
        if not os.path.exists(path):
            for alt in get_lua_init_scripts():
                if alt.endswith(name) and os.path.exists(alt):
                    path = alt
                    break
        lines.append(f"--lua-init=@{path}")
    return lines


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
) -> str:
    """Keenetic / Entware nfqws2.conf (shell env variables)."""
    quic_strategies = quic_strategies or [
        "fake:blob=quic_initial:repeats=11",
    ]
    blobs_dir = os.path.join(prefix, "blobs")
    if not os.path.isdir(blobs_dir):
        blobs_dir = BLOB_DIR

    all_strats = list(tcp_strategies) + list(udp_strategies) + list(quic_strategies)
    blob_names = extract_blob_names(*all_strats)
    for base in ("tls_clienthello", "quic_initial", "discord_udp", "stun"):
        if base not in blob_names:
            blob_names.append(base)

    base_parts = _lua_init_lines(prefix) + blob_cli_lines(blob_names, blobs_dir)
    base_args = "\n ".join(base_parts)

    # circular needs inbound until s5556 + outbound until s34228 (manual.md)
    tcp_lines = [
        "--filter-tcp=443,80,1984,5222",
        "--filter-l7=http,tls,mtproto",
        "--payload=tls_client_hello,mtproto_initial",
        "--out-range=-s34228",
        f"--in-range=-s5556 --lua-desync={CIRCULAR_TCP}",
        "--in-range=x",
    ]
    for i, strat in enumerate(tcp_strategies, start=1):
        # Multi-line strategy (fake\\nmultisplit) → one --lua-desync per line
        for part in strat.split("\n"):
            part = part.strip()
            if not part:
                continue
            tcp_lines.append(f"--lua-desync={_ensure_strategy_n(part, i)}")
    tcp_lines.extend(
        [
            "--payload=http_req",
            "--lua-desync=http_methodeol:badsum",
        ]
    )
    tcp_args = "\n ".join(tcp_lines)

    quic_lines = [
        "--filter-udp=443",
        "--filter-l7=quic",
        "--payload=quic_initial",
    ]
    for i, strat in enumerate(quic_strategies, start=1):
        for part in strat.split("\n"):
            part = part.strip()
            if not part:
                continue
            if part.startswith("--"):
                # full CLI fragment from generator
                quic_lines.append(part)
            else:
                quic_lines.append(f"--lua-desync={_ensure_strategy_n(part, i)}")
    quic_args = "\n ".join(quic_lines)

    udp_lines = [
        f"--filter-udp={DEFAULT_UDP_FILTER}",
        f"--filter-l7={DEFAULT_UDP_L7}",
        "--out-range=<n2",
        f"--payload={DEFAULT_UDP_PAYLOAD}",
        f"--lua-desync={CIRCULAR_UDP}",
    ]
    for i, strat in enumerate(udp_strategies, start=1):
        for part in strat.split("\n"):
            part = part.strip()
            if not part:
                continue
            if part.startswith("--"):
                udp_lines.append(part)
            else:
                udp_lines.append(f"--lua-desync={_ensure_strategy_n(part, i)}")
    udp_args = "\n ".join(udp_lines)

    mode_map = {
        "auto": "$MODE_AUTO",
        "list": "$MODE_LIST",
        "all": "$MODE_ALL",
    }
    extra = mode_map.get(mode.lower(), "$MODE_AUTO")

    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    hdr = [
        f"# Generated by blockcheckS nfconf at {ts}",
    ]
    if comment:
        hdr.append(f"# {comment}")
    if domains:
        hdr.append(
            f"# domains ({len(domains)}): "
            + ",".join(domains[:8])
            + ("..." if len(domains) > 8 else "")
        )
    hdr.append("# Format: nfqws2-keenetic etc/nfqws2/nfqws2.conf")
    hdr.append("")

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
) -> str:
    """Flat nfqws2 @file conf without keenetic ISP/MODE wrappers."""
    quic_strategies = quic_strategies or []
    lines: list[str] = []
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    lines.append(f"# blockcheckS raw nfqws2 conf — {ts}")
    if comment:
        lines.append(f"# {comment}")
    lines.append(f"--qnum={qnum_tcp}")
    lines.append("--ipcache-lifetime=0")
    lines.append("--bind-fix4")

    for lua in get_lua_init_scripts():
        if os.path.exists(lua):
            lines.append(f"--lua-init=@{lua}")

    all_strats = list(tcp_strategies) + list(udp_strategies) + list(quic_strategies)
    blob_names = extract_blob_names(*all_strats)
    for base in ("stun", "discord_udp", "quic_initial", "tls_clienthello", "max_ru"):
        if base not in blob_names:
            blob_names.append(base)
    lines.extend(blob_cli_lines(blob_names, blobs_dir))

    if domains:
        lines.append("--hostlist-domains=" + ",".join(domains))

    lines.append("--filter-tcp=443")
    lines.append("--filter-l3=ipv4")
    lines.append("--filter-l7=tls")
    lines.append("--payload=tls_client_hello")
    for i, strat in enumerate(tcp_strategies, start=1):
        for part in strat.split("\n"):
            part = part.strip()
            if part:
                lines.append(f"--lua-desync={_ensure_strategy_n(part, i)}")

    if quic_strategies:
        lines.append("--new=quic")
        lines.append("--filter-udp=443")
        lines.append("--filter-l7=quic")
        lines.append("--payload=quic_initial")
        for i, strat in enumerate(quic_strategies, start=1):
            for part in strat.split("\n"):
                part = part.strip()
                if not part:
                    continue
                if part.startswith("--"):
                    lines.append(part)
                else:
                    lines.append(f"--lua-desync={_ensure_strategy_n(part, i)}")

    if udp_strategies:
        lines.append("--new=voice")
        lines.append("--filter-udp=50000-50100")
        lines.append("--filter-l3=ipv4")
        lines.append("--filter-l7=discord,stun")
        lines.append("--payload=discord_ip_discovery,stun,unknown")
        for i, strat in enumerate(udp_strategies, start=1):
            for part in strat.split("\n"):
                part = part.strip()
                if not part:
                    continue
                if part.startswith("--"):
                    lines.append(part)
                else:
                    lines.append(f"--lua-desync={_ensure_strategy_n(part, i)}")

    return "\n".join(lines) + "\n"


def write_user_list(path: str, domains: list[str]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for d in domains:
            d = d.strip()
            if d and not d.startswith("#"):
                f.write(d + "\n")
