"""FamilySpec registry: expander identity plus per-family axis tables.

Axis tables live on ``FamilySpec.axes`` (see ``family_axes.FAMILY_AXES``).
Mixins, ``static_validator``, ``blob_filter``, and probe backends are untouched.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from blockchecks.engine.family_axes import FAMILY_AXES

_EMPTY_AXES: Mapping[str, object] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class FamilySpec:
    name: str
    protocols: frozenset[str]
    expander: str
    axes: Mapping[str, object]
    label_prefixes: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    triage_tags: tuple[str, ...] = ()
    default_tcp: bool = False


def _f(
    name: str,
    *protocols: str,
    prefixes: tuple[str, ...] = (),
    aliases: tuple[str, ...] = (),
    triage: tuple[str, ...] = (),
    default_tcp: bool = False,
) -> FamilySpec:
    return FamilySpec(
        name=name,
        protocols=frozenset(protocols),
        expander=f"_fam_{name}",
        axes=FAMILY_AXES[name],
        label_prefixes=prefixes,
        aliases=aliases,
        triage_tags=triage,
        default_tcp=default_tcp,
    )


# Per-tag expander order is part of the public families_for_profile contract.
TRIAGE_TO_FAMILIES: dict[str, tuple[str, ...]] = {
    "stall": ("wssize",),
    "silent_drop": ("fake", "hostfake", "fakedsplit", "multisplit", "multi_fake"),
    "rst_at_sni": ("multisplit", "fakedsplit", "multidisorder"),
    "quic_drop": ("quic_fake", "quic_ipfrag"),
    "udp_blocked": ("udp_discord",),
}

DEFAULT_FAMILIES: tuple[str, ...] = ("fake", "hostfake", "fakedsplit", "multisplit")


def _triage(name: str) -> tuple[str, ...]:
    return tuple(tag for tag, fams in TRIAGE_TO_FAMILIES.items() if name in fams)


# TCP_FAMILIES order is the generate() default and family-gate rank. Do not reorder.
REGISTRY: tuple[FamilySpec, ...] = (
    _f(
        "fake",
        "tcp",
        prefixes=("std_fake_", "fake_"),
        triage=_triage("fake"),
        default_tcp=True,
    ),
    _f("rst_fake", "tcp", prefixes=("std_rst_",)),
    _f("synack", "tcp", prefixes=("std_synack",)),
    _f("geneva_fool", "tcp", prefixes=("std_gva_",)),
    _f("wssize", "tcp", prefixes=("std_wssize",), triage=_triage("wssize")),
    _f(
        "hostfake",
        "tcp",
        prefixes=("std_hf_", "std_hostfake_", "hostfake_"),
        triage=_triage("hostfake"),
        default_tcp=True,
    ),
    _f(
        "multisplit",
        "tcp",
        prefixes=("std_split_", "std_multisplit_", "multisplit_"),
        triage=_triage("multisplit"),
        default_tcp=True,
    ),
    _f(
        "multidisorder",
        "tcp",
        prefixes=("std_mdis_", "multidisorder_"),
        triage=_triage("multidisorder"),
    ),
    _f("syndata", "tcp", prefixes=("std_syn_", "std_syndata_")),
    _f("tcpseg", "tcp", prefixes=("std_tcpseg_",)),
    _f("oob", "tcp", prefixes=("std_oob_",)),
    _f(
        "multi_fake",
        "tcp",
        prefixes=("std_multi_fake_", "std_multi_", "fake_multi_"),
        triage=_triage("multi_fake"),
    ),
    _f("triple_fake", "tcp", prefixes=("std_triple_",)),
    _f("fake_multisplit", "tcp", prefixes=("std_fms_", "fake_multisplit_")),
    _f("fake_multidisorder", "tcp", prefixes=("std_fmd_", "fake_multidisorder_")),
    _f(
        "fake_multisplit_hostfake",
        "tcp",
        prefixes=("std_fmsh_", "fake_multisplit_hostfake_"),
    ),
    _f(
        "fake_hostfake",
        "tcp",
        prefixes=("std_fake_hostfake_", "std_fh_", "fake_hostfake_"),
    ),
    _f(
        "fakedsplit",
        "tcp",
        prefixes=("std_fds_", "fakedsplit_"),
        triage=_triage("fakedsplit"),
        default_tcp=True,
    ),
    _f("fakeddisorder", "tcp", prefixes=("std_fdd_", "fakeddisorder_")),
    _f("fake_fakedsplit", "tcp", prefixes=("std_ffds_", "fake_fakedsplit_")),
    _f(
        "tcp_ipfrag",
        "tcp",
        prefixes=("std_tcp_fake_ipfrag_", "std_tcp_ipfrag_"),
        aliases=("ipfrag_tcp",),
    ),
    _f("http_simple", "http"),
    _f("http_fake", "http"),
    _f("http_tls_dual", "http"),
    _f("udp_discord", "udp_voice", triage=_triage("udp_discord")),
    _f("udp_multiblob", "udp_voice"),
    _f("quic_fake", "quic", triage=_triage("quic_fake")),
    _f("quic_gv", "quic"),
    _f(
        "quic_ipfrag",
        "quic",
        aliases=("ipfrag_udp",),
        triage=_triage("quic_ipfrag"),
    ),
    _f("udp_quic", "quic"),
    _f("udp_game", "udp_game"),
)

BY_NAME: dict[str, FamilySpec] = {s.name: s for s in REGISTRY}


def axes_for(name: str) -> Mapping[str, object]:
    spec = BY_NAME.get(name)
    return spec.axes if spec is not None else _EMPTY_AXES


TCP_FAMILIES = [s.name for s in REGISTRY if "tcp" in s.protocols]
HTTP_FAMILIES = [s.name for s in REGISTRY if "http" in s.protocols]
UDP_VOICE_FAMILIES = [s.name for s in REGISTRY if "udp_voice" in s.protocols]
QUIC_HTTP3_FAMILIES = [s.name for s in REGISTRY if "quic" in s.protocols]
UDP_QUIC_FAMILIES = [s.name for s in REGISTRY if s.name in ("udp_quic", "udp_game")]
FAMILY_ALIASES = {alias: s.name for s in REGISTRY for alias in s.aliases}
LABEL_PREFIXES: dict[str, tuple[str, ...]] = {
    s.name: s.label_prefixes for s in REGISTRY if s.label_prefixes
}
FAMILY_EXPANDERS: dict[str, str] = {s.name: s.expander for s in REGISTRY}
FAMILIES_BY_PROTOCOL: dict[str, list[str]] = {
    "udp_voice": UDP_VOICE_FAMILIES,
    "udp_game": [s.name for s in REGISTRY if "udp_game" in s.protocols],
    "http": HTTP_FAMILIES,
    "quic": QUIC_HTTP3_FAMILIES,
}
