"""Short blob names to filenames.
Search order: BLOCKCHECKS_BLOBS, repo blobs/, /opt/zapret2/blobs, /opt/zapret2/files/fake.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterable

from blockchecks.engine.config import BLOB_DIR, PROJECT_DIR, REPO_BLOBS_DIR

log = logging.getLogger(__name__)

FAKE_FILES_DIR = os.environ.get("BLOCKCHECKS_FAKE_FILES", "/opt/zapret2/files/fake")
_OPT_BLOBS = "/opt/zapret2/blobs"

# Alias → filename (under blobs dir or files/fake)
BLOB_ALIAS_MAP: dict[str, str] = {
    "google": "tls_clienthello_www_google_com.bin",
    "tls_clienthello": "tls_clienthello_www_google_com.bin",
    "max_ru": "tls_clienthello_max_ru.bin",
    "stun": "stun.bin",
    "stun2": "stun2.bin",
    "4pda": "tls_clienthello_4pda_to.bin",
    # Flowseal/custom configs spell it without the leading digit:
    # seqovl_pattern=p4da previously resolved to nothing and was silently
    # dropped from bridge confs -> Lua died per-packet on the unknown blob
    # and the probe reported "PASS without APPLIED" on clean traffic.
    "p4da": "tls_clienthello_4pda_to.bin",
    "discord_udp": "discord_udp.bin",
    "discord_ipdisc": "discord_ipdisc.bin",
    "quic_google": "quic_initial_www_google_com.bin",
    "quic_dbank": "quic_initial_dbankcloud_ru.bin",
    "quic_initial": "quic_initial.bin",
    "quic_4pda": "quic_4pda.bin",
    "quic_tencent": "quic_tencent.bin",
    "quic_steam": "quic_steam.bin",
    "quic_5ka": "quic_5ka.bin",
    "quic_rutube": "quic_rutube.bin",
    "tls_5ka": "tls_5ka.bin",
    "quic_funpay": "quic_funpay.bin",
    "quic_cloudflare": "quic_cloudflare.bin",
    "quic_alfabank": "quic_alfabank.bin",
    "tls_funpay": "tls_funpay.bin",
    "tls_rzd": "tls_rzd.bin",
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

# Flowseal / core set expected to be baked under repo blobs/
FLOWSEAL_CORE_ALIASES = (
    "stun",
    "stun2",
    "max_ru",
    "google",
    "4pda",
    "quic_google",
    "quic_dbank",
    "discord_udp",
    "game_udp",
)


def _search_bases(blobs_dir: str | None) -> list[str]:
    bases: list[str] = []
    primary = blobs_dir or BLOB_DIR
    for candidate in (
        primary,
        REPO_BLOBS_DIR,
        os.path.join(PROJECT_DIR, "blobs"),
        _OPT_BLOBS,
        FAKE_FILES_DIR,
    ):
        if candidate and candidate not in bases:
            bases.append(candidate)
    return bases


def resolve_blob_path(name: str, blobs_dir: str | None = None) -> str | None:
    """Map blob alias to absolute ``.bin`` path, or None if built-in / missing."""
    if name in _BUILTIN_BLOBS or name == "0x00000000":
        return None

    search_bases = _search_bases(blobs_dir)
    mapped = BLOB_ALIAS_MAP.get(name)

    if mapped:
        for base in search_bases:
            path = os.path.join(base, mapped)
            if os.path.isfile(path):
                return path

    for base in search_bases:
        if not os.path.isdir(base):
            continue
        exact = os.path.join(base, f"{name}.bin")
        if os.path.isfile(exact):
            return exact
        known = sorted(f for f in os.listdir(base) if f.endswith(".bin"))
        candidates = [f for f in known if name in f and "quic_initial" not in f]
        if not candidates:
            candidates = [f for f in known if name in f]
        if candidates:
            chosen = os.path.join(base, candidates[0])
            log.warning("%s", f"  WARNING: fuzzy blob {name!r} -> {candidates[0]}")
            return chosen

    if mapped:
        for base in search_bases:
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
    rename_map: dict[str, str] | None = None,
) -> dict[str, str]:
    """Append unique ``--blob=NAME:@path`` lines for each resolvable name.

    Returns the rename map applied (original -> conf-safe identifier) plus
    entries for unresolvable names mapped to "" — callers must rewrite
    strategy text accordingly. nfqws2 rejects identifiers starting with a
    digit ("bad identifier '4pda'") and EXITS AT STARTUP, killing the whole
    batch; such names are emitted as ``b<name>`` and strategy references are
    renamed to match. Unresolvable names are logged loudly — a missing blob
    dies per-packet at runtime (no APPLIED event, clean-traffic probes).
    """
    renames: dict[str, str] = dict(rename_map or {})
    for name in names:
        safe = renames.get(name)
        if safe is None:
            safe = safe_blob_name(name)
            renames[name] = safe
        if not safe:
            continue  # already reported as unresolvable
        if any(line.startswith(f"--blob={safe}:@") for line in lines):
            continue
        cli = blob_cli_line(name, blobs_dir)
        if cli:
            lines.append(f"--blob={safe}:@{cli.split(':@', 1)[1]}")
        else:
            renames[name] = ""
            log.warning(
                "%s",
                f"  WARNING: blob {name!r} not resolvable in "
                f"{blobs_dir or BLOB_DIR} (searched aliases + repo/vendor dirs) — "
                f"strategy will fail at runtime; add the .bin or fix the alias",
            )
    return renames


_BLOB_SAFE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def safe_blob_name(name: str) -> str:
    """nfqws2-safe blob identifier (must not start with a digit)."""
    return name if _BLOB_SAFE_RE.match(name) else f"b{name}"


def apply_blob_renames(text: str, renames: dict[str, str]) -> str:
    """Rewrite blob=/pattern=/seqovl_pattern= references per *renames*."""
    if not renames:
        return text
    for orig, safe in renames.items():
        if not orig or not safe or orig == safe:
            continue
        text = re.sub(
            rf"((?:blob|pattern|seqovl_pattern)=){re.escape(orig)}\b",
            rf"\g<1>{safe}",
            text,
        )
    return text


def blob_cli_lines(names: Iterable[str], blobs_dir: str | None = None) -> list[str]:
    """Return ``--blob=NAME:@path`` lines for resolvable names."""
    out: list[str] = []
    append_blob_cli_lines(out, names, blobs_dir)
    return out


# Shipped by nfqws2-keenetic under /opt/etc/nfqws2/blobs/ — no COPY comment.
STOCK_KEENETIC_BLOB_FILES = frozenset({"tls_clienthello.bin", "quic_initial.bin"})


def blob_export_filename(name: str) -> str | None:
    """Filename under prefix/blobs for *name*, or None if built-in / hex."""
    if name in _BUILTIN_BLOBS or name == "0x00000000":
        return None
    return BLOB_ALIAS_MAP.get(name) or f"{name}.bin"


def blob_export_cli_line(name: str, prefix: str) -> str | None:
    """``--blob=NAME:@{prefix}/blobs/file.bin`` without host-path resolution."""
    fname = blob_export_filename(name)
    if not fname:
        return None
    return f"--blob={name}:@{prefix}/blobs/{fname}"
