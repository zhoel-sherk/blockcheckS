"""Shared helpers + StrategyParams for strategy-family expansion (standard.py).

Pure string/validation utilities — no generator state. Kept here so the
``families.*`` modules (split/fake/tamper) stay free of cross-imports.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from blockchecks.engine.blob_aliases import BLOB_ALIAS_MAP, resolve_blob_path
from blockchecks.engine.config import BLOB_DIR


def _ttl_clause(ttl_val: str) -> str:
    if not ttl_val:
        return ""
    if "-" in str(ttl_val) and "," in str(ttl_val):
        return f":ip_autottl={ttl_val}"
    return f":ip_ttl={ttl_val}"


def _fooling_clause(fool: str) -> str:
    if not fool:
        return ""
    return f":{fool}"


def _with_ack_drop(core: str) -> str:
    """BC2 ACK-drop companion: empty ACK with pktmod ttl=1 (25/30/35-fake*)."""
    return f"{core}\n--payload=empty --out-range=s1<d1\npktmod:ip_ttl=1"


def _with_send_md5(core: str) -> str:
    """BC2 duplicate SYN with MD5 when fooling includes tcp_md5."""
    return f"{core}\n--payload=empty --out-range=<s1\nsend:tcp_md5"


def _with_ip6_send_drop(fool: str) -> str:
    """BC2 90-quic.sh IPv6 send+drop companion."""
    return f"send:{fool}\ndrop"


def _blob_file(alias: str) -> str:
    """Resolve alias to filename under zapret2 blobs dir."""
    return BLOB_ALIAS_MAP.get(alias, f"{alias}.bin")


def _blob_abs(alias: str) -> str:
    """Absolute blob path via resolve_blob_path, fallback to BLOB_DIR/filename."""
    return resolve_blob_path(alias) or os.path.join(BLOB_DIR, _blob_file(alias))


@dataclass(frozen=True, slots=True)
class StrategyParams:
    """Validated, normalized axes for one strategy-family expansion.

    Converts free-form family dicts into typed, defaulted values so flag
    spelling mistakes (e.g. ``foolings`` vs ``fooling``, wrong ``repeats``
    type) surface early instead of silently producing empty pools.
    """

    protocol: str = "tls12"
    scan_level: str = "fast"
    repeats: tuple[int, ...] = (6,)
    foolings: tuple[str, ...] = ("",)
    blobs: tuple[str, ...] = ()
    ttl_static: tuple[int, ...] = ()
    ttl_auto: tuple[str, ...] = ()
    positions: tuple[str, ...] = ()
    tls_mods: tuple[str, ...] = ()
    ack_drop: bool = False
    send_md5: bool = False

    @staticmethod
    def from_family(family: dict, **overrides) -> StrategyParams:
        def _ints(key: str) -> tuple[int, ...]:
            return tuple(int(v) for v in family.get(key, ()))

        def _strs(key: str) -> tuple[str, ...]:
            return tuple(str(v) for v in family.get(key, ()))

        return StrategyParams(
            protocol=str(overrides.get("protocol", "tls12")),
            scan_level=str(overrides.get("scan_level", "fast")),
            repeats=_ints("repeats") or (6,),
            foolings=_strs("foolings") or ("",),
            blobs=_strs("blobs"),
            ttl_static=_ints("ttl_static"),
            ttl_auto=_strs("ttl_auto"),
            positions=_strs("positions"),
            tls_mods=_strs("tls_mods"),
            ack_drop=bool(family.get("ack_drop", False)),
            send_md5=bool(family.get("send_md5", False)),
        )


def _static_numeric_split(strategy: str) -> bool:
    """True if the strategy splits ONLY at static numeric positions.

    Post-quantum ClientHellos are ~1500-1800B (2 TCP segments), so a split at a
    bare number (``pos=2``) may land mid-record. Strategies that include any
    contextual marker (``sniext``, ``sni``, ``host``, ``midsld``, …) stay valid.
    """
    pos_values: list[str] = []
    for m in re.finditer(r"pos=([^:]+)", strategy):
        pos_values.append(m.group(1))
    if not pos_values:
        return False
    return all(not re.search(r"[A-Za-z]", value) for value in pos_values)
