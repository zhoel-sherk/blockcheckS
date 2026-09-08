"""Filter blob classes and enable custom Lua from a TriageProfile."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from blockchecks.engine.blob_aliases import BLOB_ALIAS_MAP
from blockchecks.engine.conf_builder import load_custom_lua_manifest
from blockchecks.engine.family_registry import triage_tags

if TYPE_CHECKING:
    from blockchecks.engine.triage import TriageProfile

log = logging.getLogger(__name__)

BLOB_CLASS_MAP: dict[str, str] = {
    "stun": "stun",
    "stun2": "stun",
    "google": "tls_clienthello",
    "tls_clienthello": "tls_clienthello",
    "max_ru": "tls_clienthello",
    "4pda": "tls_clienthello",
    "tls_vk": "tls_clienthello",
    "tls_5ka": "tls_clienthello",
    "tls_funpay": "tls_clienthello",
    "tls_rzd": "tls_clienthello",
    "discord_udp": "discord_udp",
    "discord_ipdisc": "discord_udp",
    "game_udp": "game_udp",
    "quic_google": "quic",
    "quic_initial": "quic",
    "quic_dbank": "quic",
    "quic_4pda": "quic",
    "quic_vk": "quic",
    "quic_tencent": "quic",
    "quic_steam": "quic",
    "quic_5ka": "quic",
    "quic_rutube": "quic",
    "quic_funpay": "quic",
    "quic_cloudflare": "quic",
    "quic_alfabank": "quic",
    "quic_gv_kyber": "quic",
    "quic_gv_kyber_1": "quic",
    "quic_gv_kyber_2": "quic",
    "quic_gv_rr2": "quic",
}

_QUIC_PREFIX = "quic_"
_TLS_PREFIX = "tls_"

# Upstream built-ins / null fakes are canonical forms the triage blob-grid
# cannot represent (it probes classes on TLS payload only). They are never
# pruned by viable_blobs — AUDIT §7.1: http_fake/syndata emptied entirely,
# quic_fake lost fake_default_quic, fake lost the null fake.
_BUILTIN_BLOB_CLASSES: dict[str, str] = {
    "fake_default_tls": "tls_clienthello",
    "fake_default_http": "tls_clienthello",
    "fake_default_quic": "quic",
}
_NULL_BLOBS = frozenset({"0x00000000", "0x1603"})
# Bare "" means "no blob core" (blob_class → "other"), still never pruned.
_ALWAYS_KEEP = frozenset(_BUILTIN_BLOB_CLASSES) | _NULL_BLOBS | {""}


def blob_class(alias: str) -> str:
    """Coarse class for a blob alias (stun / tls_clienthello / quic / …)."""
    if alias in BLOB_CLASS_MAP:
        return BLOB_CLASS_MAP[alias]
    if alias in _BUILTIN_BLOB_CLASSES:
        return _BUILTIN_BLOB_CLASSES[alias]
    if alias in _NULL_BLOBS:
        return "empty"
    if alias.startswith(_QUIC_PREFIX):
        return "quic"
    if alias.startswith(_TLS_PREFIX):
        return "tls_clienthello"
    return "other"


def aliases_for_class(cls: str) -> list[str]:
    """Blob aliases that belong to *cls* (class name itself included)."""
    mapped = [a for a, c in BLOB_CLASS_MAP.items() if c == cls or a == cls]
    builtins = [a for a, c in _BUILTIN_BLOB_CLASSES.items() if c == cls]
    return sorted(set([*mapped, *builtins]))


def filter_blob_aliases(
    aliases: list[str] | tuple[str, ...] | None,
    profile: TriageProfile | None,
    protocol: str = "tcp",
) -> list[str]:
    """Keep aliases whose class (or name) is in ``profile.viable_blobs``.

    Empty ``viable_blobs`` → no filter (unknown, keep everything).
    Protocol-aware: TCP TLS blob grid viability (stun, tls_clienthello) applies
    to TLS/HTTP blobs; UDP and QUIC blobs are not pruned by TCP TLS preflight.
    Built-ins (fake_default_*) and null/hex blobs are always kept — the grid
    cannot prove them dead (AUDIT §7.1). Warn when the filter would empty a
    non-empty pool (matrix shrink must stay visible).
    """
    pool = list(aliases) if aliases is not None else list(BLOB_ALIAS_MAP)
    if profile is None or not profile.viable_blobs:
        return pool
    allowed = set(profile.viable_blobs)
    kept = [
        a
        for a in pool
        if a in _ALWAYS_KEEP
        or a in allowed
        or blob_class(a) in allowed
        or (protocol in ("udp_voice", "udp_game", "quic") and blob_class(a) in ("discord_udp", "game_udp", "quic"))
    ]
    if pool and not kept:
        log.warning(
            "%s",
            f"  blob filter: all {len(pool)} blobs pruned by viable_blobs="
            f"{sorted(allowed)} (protocol={protocol}) — family will be empty",
        )
    return kept


def lua_entries_for_triage(profile: TriageProfile | None) -> list[dict]:
    """Manifest rows whose ``requires_triage`` matches the profile tags."""
    tags = set(triage_tags(profile)) if profile is not None else set()
    return [
        {"name": name, **meta}
        for name, meta in load_custom_lua_manifest().items()
        if _lua_matches(meta, tags)
    ]


def _lua_matches(meta: dict, tags: set[str]) -> bool:
    required = [str(t) for t in (meta.get("requires_triage") or [])]
    return not required or bool(tags & set(required))


def lua_files_for_triage(profile: TriageProfile | None) -> list[str]:
    """Custom Lua filenames to pass as ``--lua-extra`` for this profile."""
    return list(dict.fromkeys(e["file"] for e in lua_entries_for_triage(profile)))
