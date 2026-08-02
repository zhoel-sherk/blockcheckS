"""Build nfqws2 config text: keenetic shell-env and raw flat conf."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Iterable

from blockchecks.engine.blob_aliases import resolve_blob_path as _resolve_blob_path
from blockchecks.engine.config import BLOB_DIR, LUA_INIT_SCRIPTS

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


def extract_blob_names(*strategies: str) -> list[str]:
    """Unique blob=/seqovl_pattern= names from strategy strings."""
    names: list[str] = []
    seen: set[str] = set()
    for strat in strategies:
        if not strat:
            continue
        for m in re.finditer(r"(?:blob|seqovl_pattern)=(\w+)", strat):
            n = m.group(1)
            if n in seen or n == "0x00000000":
                continue
            seen.add(n)
            names.append(n)
    return names


def resolve_blob_path(name: str, blobs_dir: str) -> str | None:
    """Map blob name → absolute .bin path under blobs_dir."""
    return _resolve_blob_path(name, blobs_dir)


def blob_cli_lines(names: Iterable[str], blobs_dir: str) -> list[str]:
    lines = []
    for name in names:
        path = resolve_blob_path(name, blobs_dir)
        if path:
            lines.append(f"--blob={name}:@{path}")
    return lines


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
            for alt in LUA_INIT_SCRIPTS:
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

    tcp_lines = [
        "--filter-tcp=443,80,1984,5222",
        "--filter-l7=http,tls,mtproto",
        "--payload=tls_client_hello,mtproto_initial",
        f"--lua-desync={CIRCULAR_TCP}",
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

    for lua in LUA_INIT_SCRIPTS:
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
