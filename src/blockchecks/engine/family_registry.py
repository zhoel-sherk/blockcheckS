"""Map TriageProfile to expander names in StandardGenerator / MatrixGenerator and prune the matrix."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING

from blockchecks.engine.fail_phase import FailPhase
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.generators.families._helpers import _static_numeric_split

if TYPE_CHECKING:
    from blockchecks.engine.triage import TriageProfile

DEFAULT_FAMILIES: tuple[str, ...] = ("fake", "hostfake", "fakedsplit", "multisplit")

TRIAGE_TO_FAMILIES: dict[str, tuple[str, ...]] = {
    "stall": ("wssize",),
    "silent_drop": ("fake", "hostfake", "fakedsplit", "multisplit", "multi_fake"),
    "rst_at_sni": ("multisplit", "fakedsplit", "multidisorder"),
    "quic_drop": ("quic_fake", "quic_ipfrag"),
    "udp_blocked": ("udp_discord",),
}

_GRID_FOOLINGS: tuple[str, ...] = (
    "badsum",
    "tcp_md5",
    "tcp_ts",
    "tcp_seq",
    "badsid",
    "tcp_ack",
)
# Grid cell ``tcp_seq=1000`` is the sequence-number probe; badsid is the same class.
_FOOLING_EQUIV: dict[str, tuple[str, ...]] = {
    "tcp_seq": ("tcp_seq", "badsid"),
    "badsid": ("tcp_seq", "badsid"),
}
_FOOL_TOKEN_RE = re.compile(
    r"(badsum|tcp_md5|badsid|tcp_ts|tcp_seq|tcp_ack|send)(?:=|:|$)",
)
_IP_TTL_RE = re.compile(r"ip_ttl=(\d+)")


def triage_tags(profile: TriageProfile) -> list[str]:
    """Active triage tags in priority order (deduped)."""
    checks: tuple[tuple[str, Callable[[TriageProfile], bool]], ...] = (
        ("stall", lambda p: p.requires_window_clamp),
        ("silent_drop", lambda p: p.silent_drop_after_sni),
        ("rst_at_sni", lambda p: p.rst_at_sni or p.handshake_phase == FailPhase.TLS_RST_AT_SNI),
        ("quic_drop", lambda p: p.quic_drop),
        ("udp_blocked", lambda p: p.udp_blocked),
    )
    return [tag for tag, pred in checks if pred(profile)]


def families_for_profile(profile: TriageProfile | None) -> list[str]:
    """Ordered unique expander names for *profile* (MCP + generator filter)."""
    if profile is None:
        return list(DEFAULT_FAMILIES)
    families: list[str] = []
    for tag in triage_tags(profile):
        families.extend(TRIAGE_TO_FAMILIES[tag])
    return list(dict.fromkeys(families)) or list(DEFAULT_FAMILIES)


def dead_fooling_tokens(profile: TriageProfile | None) -> tuple[str, ...]:
    """Grid foolings proven non-viable (empty when the grid was not run)."""
    if profile is None:
        return ()
    extra = tuple(_fooling_key(x) for x in profile.dead_foolings)
    if not profile.viable_foolings:
        return extra
    viable = {
        tok
        for fool in profile.viable_foolings
        for tok in _FOOLING_EQUIV.get(_fooling_key(fool), (_fooling_key(fool),))
    }
    return tuple(dict.fromkeys([*(tok for tok in _GRID_FOOLINGS if tok not in viable), *extra]))


def _fooling_key(token: str) -> str:
    return token.split("=", 1)[0].split(":", 1)[0]


def strategy_fooling_keys(strategy: str) -> set[str]:
    """Fooling token names present in a strategy or a single axis value."""
    return set(_FOOL_TOKEN_RE.findall(strategy))


def filter_fooling_values(fools: list[str] | tuple[str, ...], profile: TriageProfile | None) -> list[str]:
    """Drop fooling axis values the viability grid proved dead."""
    dead = set(dead_fooling_tokens(profile))
    if not dead:
        return list(fools)
    return [f for f in fools if not (strategy_fooling_keys(f":{f}") & dead)]


def filter_ttl_values(
    ttls: list | tuple,
    profile: TriageProfile | None,
    *,
    scan_level: str = "fast",
) -> list:
    """Drop static ``ip_ttl`` values that miss DPI or reach the origin."""
    if profile is None or scan_level == "full":
        return list(ttls)
    dpi, server = profile.dpi_hops, profile.server_hops
    if dpi is None and server is None:
        return list(ttls)
    return [ttl for ttl in ttls if _ttl_axis_ok(ttl, dpi, server)]


def _ttl_axis_ok(ttl: object, dpi: int | None, server: int | None) -> bool:
    if isinstance(ttl, str) and not ttl.lstrip("-").isdigit():
        return True
    try:
        n = int(ttl)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return True
    return _ttl_ok(f"ip_ttl={n}", dpi, server)


def filter_split_positions(
    positions: list | tuple,
    profile: TriageProfile | None,
    *,
    scan_level: str = "fast",
) -> list:
    """Keep split positions compatible with ``profile.split_mode``."""
    if profile is None or scan_level == "full" or not profile.split_mode:
        return list(positions)
    mode = profile.split_mode
    return [p for p in positions if _pos_ok(str(p), mode)]


def _pos_ok(pos: str, mode: str) -> bool:
    if mode == "first_byte":
        return "sniext" not in pos
    if mode == "sni_marker":
        return pos != "1" and not pos.startswith("1,")
    return True


def prune_items_by_triage(
    items: list[StrategyItem],
    profile: TriageProfile | None,
    *,
    scan_level: str = "fast",
) -> list[StrategyItem]:
    """Drop strategies the preflight proved useless. No-op when profile is empty."""
    if profile is None:
        return items
    if not profile.bypassable:
        return []
    dead = set(dead_fooling_tokens(profile))
    full = scan_level == "full"
    dpi = None if full else profile.dpi_hops
    server = None if full else profile.server_hops
    contextual = profile.prefer_contextual_split
    split_mode = "" if full else profile.split_mode
    return [it for it in items if _item_survives(it, profile, dead, dpi, server, contextual, split_mode)]


def _item_survives(
    item: StrategyItem,
    profile: TriageProfile,
    dead: set[str],
    dpi: int | None,
    server: int | None,
    contextual: bool,
    split_mode: str,
) -> bool:
    strat = item.strategy
    if dead and strategy_fooling_keys(strat) & dead:
        return False
    if not _ttl_ok(strat, dpi, server):
        return False
    if not _blob_ok(strat, profile):
        return False
    if contextual and _static_numeric_split(strat):
        return False
    if split_mode == "first_byte" and "sniext" in strat:
        return False
    return not (split_mode == "sni_marker" and re.search(r"pos=1(?:,|$)", strat))


def _blob_ok(strategy: str, profile: TriageProfile) -> bool:
    aliases = re.findall(r"blob=([A-Za-z0-9_]+)", strategy)
    if not aliases or not profile.viable_blobs:
        return True
    from blockchecks.engine.blob_filter import filter_blob_aliases

    return bool(filter_blob_aliases(aliases, profile))


def _ttl_ok(strategy: str, dpi_hops: int | None, server_hops: int | None) -> bool:
    if dpi_hops is None and server_hops is None:
        return True
    m = _IP_TTL_RE.search(strategy)
    if not m:
        return True
    ttl = int(m.group(1))
    if dpi_hops is not None and ttl < dpi_hops:
        return False
    return not (server_hops is not None and ttl >= server_hops)
