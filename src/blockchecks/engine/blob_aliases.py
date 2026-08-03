"""Canonical blob alias → file map (BLOB-3).

Strategy strings use short names (`google`, `quic_gv_kyber_1`, …). Resolution
checks ``BLOCKCHECKS_BLOBS`` then ``/opt/zapret2/files/fake``.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable

from blockchecks.engine.config import BLOB_DIR

FAKE_FILES_DIR = os.environ.get("BLOCKCHECKS_FAKE_FILES", "/opt/zapret2/files/fake")

# Alias → filename (under blobs dir or files/fake)
BLOB_ALIAS_MAP: dict[str, str] = {
    "google": "tls_clienthello_www_google_com.bin",
    "tls_clienthello": "tls_clienthello_www_google_com.bin",
    "max_ru": "tls_clienthello_max_ru.bin",
    "stun": "stun.bin",
    "stun2": "stun2.bin",
    "4pda": "tls_clienthello_4pda_to.bin",
    "discord_udp": "discord_udp.bin",
    "discord_ipdisc": "discord_ipdisc.bin",
    "quic_google": "quic_initial_www_google_com.bin",
    "quic_dbank": "quic_initial_dbankcloud_ru.bin",
    "quic_initial": "quic_initial.bin",
    "quic_4pda": "quic_4pda.bin",
    "quic_tencent": "quic_tencent.bin",
    "quic_steam": "quic_steam.bin",
    "quic_gv_kyber": "quic_gv_kyber_1.bin",
    "quic_gv_kyber_1": "quic_gv_kyber_1.bin",
    "quic_gv_kyber_2": "quic_gv_kyber_2.bin",
    "quic_gv_rr2": "quic_gv_rr2.bin",
    "tls_vk": "tls_clienthello_vk_com.bin",
    "quic_vk": "quic_initial_vk_com.bin",
    "game_udp": "game_udp.bin",
    "wireguard_init": "wireguard_init.bin",
    "http_iana": "http_iana.bin",
}

_BUILTIN_BLOBS = frozenset({"fake_default_tls", "fake_default_http", "fake_default_quic"})
_BLOB_NAME_RE = re.compile(r"(?:blob|pattern|seqovl_pattern)=(\w+)")


def resolve_blob_path(name: str, blobs_dir: str | None = None) -> str | None:
    """Map blob alias to absolute ``.bin`` path, or None if built-in / missing."""
    if name in _BUILTIN_BLOBS or name == "0x00000000":
        return None

    blobs_dir = blobs_dir or BLOB_DIR
    search_bases = [blobs_dir]
    if FAKE_FILES_DIR and blobs_dir != FAKE_FILES_DIR:
        search_bases.append(FAKE_FILES_DIR)

    mapped = BLOB_ALIAS_MAP.get(name)
    if mapped:
        for base in search_bases:
            path = os.path.join(base, mapped)
            if os.path.isfile(path):
                return path

    if not os.path.isdir(blobs_dir):
        exact = os.path.join(blobs_dir, f"{name}.bin")
        return exact if os.path.exists(exact) else None

    known = sorted(f for f in os.listdir(blobs_dir) if f.endswith(".bin"))
    candidates = [f for f in known if name in f and "quic_initial" not in f]
    if not candidates:
        candidates = [f for f in known if name in f]
    if candidates:
        return os.path.join(blobs_dir, candidates[0])

    exact = os.path.join(blobs_dir, f"{name}.bin")
    if os.path.exists(exact):
        return exact

    if mapped:
        for base in search_bases:
            # Long zapret stock names (e.g. quic_initial_*_googlevideo_com_kyber_1.bin)
            if not os.path.isdir(base):
                continue
            for fname in os.listdir(base):
                if not fname.endswith(".bin"):
                    continue
                stem = fname[:-4]
                if stem == mapped[:-4] or name in stem:
                    return os.path.join(base, fname)

    return None


def extract_blob_names(*strategies: str) -> list[str]:
    """Unique blob=/pattern=/seqovl_pattern= names from strategy strings."""
    names: list[str] = []
    seen: set[str] = set()
    for strat in strategies:
        if not strat:
            continue
        for m in _BLOB_NAME_RE.finditer(strat):
            n = m.group(1)
            if n in seen or n == "0x00000000":
                continue
            seen.add(n)
            names.append(n)
    return names


def blob_cli_line(name: str, blobs_dir: str | None = None) -> str | None:
    """Format ``--blob=NAME:@path`` or None if unresolved / built-in."""
    if name == "0x00000000":
        return None
    path = resolve_blob_path(name, blobs_dir)
    return f"--blob={name}:@{path}" if path else None


def append_blob_cli_lines(
    lines: list[str],
    names: Iterable[str],
    blobs_dir: str | None = None,
) -> None:
    """Append unique ``--blob=NAME:@path`` lines for each resolvable name."""
    for name in names:
        if any(line.startswith(f"--blob={name}:@") for line in lines):
            continue
        cli = blob_cli_line(name, blobs_dir)
        if cli:
            lines.append(cli)


def blob_cli_lines(names: Iterable[str], blobs_dir: str | None = None) -> list[str]:
    """Return ``--blob=NAME:@path`` lines for resolvable names."""
    out: list[str] = []
    append_blob_cli_lines(out, names, blobs_dir)
    return out
