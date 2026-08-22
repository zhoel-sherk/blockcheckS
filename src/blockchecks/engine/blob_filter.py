"""Filter blob classes and enable custom Lua from a TriageProfile."""

from __future__ import annotations

from typing import TYPE_CHECKING

from blockchecks.engine.blob_aliases import BLOB_ALIAS_MAP
from blockchecks.engine.conf_builder import load_custom_lua_manifest
from blockchecks.engine.family_registry import triage_tags

if TYPE_CHECKING:
    from blockchecks.engine.triage import TriageProfile

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


def blob_class(alias: str) -> str:
    """Coarse class for a blob alias (stun / tls_clienthello / quic / …)."""
    if alias in BLOB_CLASS_MAP:
        return BLOB_CLASS_MAP[alias]
    if alias.startswith(_QUIC_PREFIX):
        return "quic"
    if alias.startswith(_TLS_PREFIX):
        return "tls_clienthello"
    return "other"


def aliases_for_class(cls: str) -> list[str]:
    """Blob aliases that belong to *cls* (class name itself included)."""
    return [a for a, c in BLOB_CLASS_MAP.items() if c == cls or a == cls]


def filter_blob_aliases(
    aliases: list[str] | tuple[str, ...] | None,
    profile: TriageProfile | None,
    protocol: str = "tcp",
) -> list[str]:
    """Keep aliases whose class (or name) is in ``profile.viable_blobs``.

    Empty ``viable_blobs`` → no filter (unknown, keep everything).
    Protocol-aware: TCP TLS blob grid viability (stun, tls_clienthello) applies
    to TLS/HTTP blobs; UDP and QUIC blobs are not pruned by TCP TLS preflight.
    """
    pool = list(aliases) if aliases is not None else list(BLOB_ALIAS_MAP)
    if profile is None or not profile.viable_blobs:
        return pool
    allowed = set(profile.viable_blobs)
    return [
        a
        for a in pool
        if a in allowed
        or blob_class(a) in allowed
        or (protocol in ("udp_voice", "udp_game", "quic") and blob_class(a) in ("discord_udp", "game_udp", "quic"))
    ]


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
