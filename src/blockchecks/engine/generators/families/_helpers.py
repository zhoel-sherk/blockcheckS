"""Shared string helpers and StrategyParams for family expanders. No generator state."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from itertools import product

AddFn = Callable[..., None]


def _ttl_clause(ttl_val: str | int | None) -> str:
    if ttl_val is None or ttl_val == "":
        return ""
    text = str(ttl_val)
    if "-" in text and "," in text:
        return f":ip_autottl={text}"
    return f":ip_ttl={text}"


def _fooling_clause(fool: str) -> str:
    if not fool:
        return ""
    return f":{fool}"


def required_foolings(fools: Iterable[str]) -> tuple[str, ...]:
    """Drop empty fooling — hidden-fake cores need a fool or origin may accept the fake."""
    return tuple(f for f in fools if f)


def _with_ack_drop(core: str) -> str:
    """BC2 ACK-drop companion: empty ACK with pktmod ttl=1 (25/30/35-fake*)."""
    return f"{core}\n--payload=empty --out-range=s1<d1\npktmod:ip_ttl=1"


def _with_send_md5(core: str) -> str:
    """BC2 duplicate SYN with MD5 when fooling includes tcp_md5."""
    return f"{core}\n--payload=empty --out-range=<s1\nsend:tcp_md5"


def _with_ip6_send_drop(fool: str) -> str:
    """BC2 90-quic.sh IPv6 send+drop companion."""
    return f"send:{fool}\ndrop"


def _axis_vals(v: Iterable) -> tuple:
    return (v,) if isinstance(v, (str, bytes)) else tuple(v)


def expand_axes(
    axes: Mapping[str, Iterable],
    build: Callable[[dict], tuple[str, str]],
) -> list[tuple[str, str]]:
    keys = list(axes)
    return [
        build(dict(zip(keys, vals, strict=True)))
        for vals in product(*(_axis_vals(axes[k]) for k in keys))
    ]


def emit_rows(
    add: AddFn,
    items: list,
    seen: set,
    scan_level: str,
    rows: Iterable[tuple[str, str]],
    *,
    protocol: str = "tls12",
) -> bool:
    """True if caller should stop (single)."""
    for label, strat in rows:
        add(items, seen, label, strat, protocol=protocol)
        if scan_level == "single":
            return True
    return False


def ttl_companion_rows(
    label: str,
    strat: str,
    static: Iterable,
    auto: Iterable,
    *,
    auto_fmt: str = "autottl{ttl}",
) -> list[tuple[str, str]]:
    return [
        *[(f"{label}_ttl{t}", f"{strat}{_ttl_clause(t)}") for t in static],
        *[(f"{label}_{auto_fmt.format(ttl=t)}", f"{strat}{_ttl_clause(t)}") for t in auto],
    ]


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
    blob_pairs: tuple[tuple[str, ...], ...] = ()
    pattern_blobs: tuple[str, ...] = ()
    seqovl_blobs: tuple[str, ...] = ()
    seqovl: tuple[int, ...] = ()
    variants: tuple[str, ...] = ()
    fools: tuple[str, ...] = ()
    out_range: tuple = ()
    profiles: tuple[tuple[str, ...], ...] = ()
    triples: tuple[tuple[str, ...], ...] = ()
    hf_hosts: tuple[str, ...] = ()
    hf_variants: tuple[str, ...] = ()

    @staticmethod
    def from_family(family: dict, **overrides) -> StrategyParams:
        def _ints(key: str) -> tuple[int, ...]:
            return tuple(int(v) for v in family.get(key, ()))

        def _strs(key: str) -> tuple[str, ...]:
            return tuple(str(v) for v in family.get(key, ()))

        def _pairs(key: str) -> tuple[tuple[str, ...], ...]:
            return tuple(tuple(str(x) for x in row) for row in family.get(key, ()))

        fields = dict(
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
            blob_pairs=_pairs("blob_pairs"),
            pattern_blobs=_strs("pattern_blobs"),
            seqovl_blobs=_strs("seqovl_blobs"),
            seqovl=_ints("seqovl"),
            variants=_strs("variants"),
            fools=_strs("fools"),
            out_range=tuple(family.get("out_range", ())),
            profiles=_pairs("profiles"),
            triples=_pairs("triples"),
            hf_hosts=_strs("hf_hosts"),
            hf_variants=_strs("hf_variants"),
        )
        fields.update({k: v for k, v in overrides.items() if k in StrategyParams.__slots__})
        return StrategyParams(**fields)


def _static_numeric_split(strategy: str) -> bool:
    """True if the strategy splits ONLY at static numeric positions.

    Post-quantum ClientHellos are ~1500-1800B (2 TCP segments), so a split at a
    bare number (``pos=2``) may land mid-record. Strategies that include any
    contextual marker (``sniext``, ``sni``, ``host``, ``midsld``, …) stay valid.
    """
    pos_values = [m.group(1) for m in re.finditer(r"pos=([^:]+)", strategy)]
    if not pos_values:
        return False
    return all(not re.search(r"[A-Za-z]", value) for value in pos_values)
