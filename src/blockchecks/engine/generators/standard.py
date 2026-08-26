"""Standard nfqws2 strategy families. Facade over families/split, fake, and tamper."""

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING

import blockchecks.engine.family_spec as _family_spec
from blockchecks.engine import family_axes as _family_axes
from blockchecks.engine.family_spec import axes_for
from blockchecks.engine.generators.base import StrategyGenerator, StrategyItem
from blockchecks.engine.generators.families import (
    FakeFamiliesMixin,
    SplitFamiliesMixin,
    TamperFamiliesMixin,
)
from blockchecks.engine.store import RunStateStore

ALL_FOOLINGS_IPV6 = _family_axes.ALL_FOOLINGS_IPV6
ALL_FOOLINGS_TCP = _family_axes.ALL_FOOLINGS_TCP
ALL_FOOLINGS_UDP = _family_axes.ALL_FOOLINGS_UDP
ALL_REPEATS = _family_axes.ALL_REPEATS
ALL_TTL = _family_axes.ALL_TTL
FAST_FOOLINGS_IPV6 = _family_axes.FAST_FOOLINGS_IPV6
FAST_FOOLINGS_TCP = _family_axes.FAST_FOOLINGS_TCP
FAST_REPEATS = _family_axes.FAST_REPEATS
TLS_MODS = _family_axes.TLS_MODS

FAMILY_ALIASES = _family_spec.FAMILY_ALIASES
FAMILY_EXPANDERS = _family_spec.FAMILY_EXPANDERS
HTTP_FAMILIES = _family_spec.HTTP_FAMILIES
QUIC_HTTP3_FAMILIES = _family_spec.QUIC_HTTP3_FAMILIES
TCP_FAMILIES = _family_spec.TCP_FAMILIES
UDP_QUIC_FAMILIES = _family_spec.UDP_QUIC_FAMILIES
UDP_VOICE_FAMILIES = _family_spec.UDP_VOICE_FAMILIES
_FAMILIES_BY_PROTOCOL = _family_spec.FAMILIES_BY_PROTOCOL

if TYPE_CHECKING:
    from blockchecks.engine.triage import TriageProfile


def _resolve_family_name(name: str) -> str:
    return FAMILY_ALIASES.get(name, name)


def _round_robin(groups: dict[str, list[StrategyItem]], cap: int) -> list[StrategyItem]:
    """Interleave one item per family so a cap cannot starve later families."""
    out, seen_out, idx = [], set(), 0
    order = list(groups)
    while len(out) < cap:
        advanced = False
        for t in order:
            lst = groups[t]
            if idx >= len(lst):
                continue
            it = lst[idx]
            if it.strategy not in seen_out:
                seen_out.add(it.strategy)
                out.append(it)
            advanced = True
            if len(out) >= cap:
                break
        if not advanced:
            break
        idx += 1
    return out


def _mut_full_fake(fam: dict) -> None:
    fam["repeats"] = [r for r in ALL_REPEATS if r not in (100, 260)]
    fam["foolings"] = ALL_FOOLINGS_TCP + ALL_FOOLINGS_IPV6
    fam["tls_mods"] = TLS_MODS


def _mut_full_tcp_fools(fam: dict) -> None:
    fam["foolings"] = list(dict.fromkeys([*fam.get("foolings", []), *ALL_FOOLINGS_TCP]))


def _mut_full_quic_fake(fam: dict) -> None:
    fam["foolings"] = list(dict.fromkeys([*fam.get("foolings", [""]), *ALL_FOOLINGS_UDP]))
    fam["ip6_fools"] = ALL_FOOLINGS_IPV6


def _mut_full_udp_discord(fam: dict) -> None:
    fam["repeats"] = [2, 3, 4, 6, 8, 10, 12, 14]
    fam["ttl_static"] = [5, 8]
    fam["ttl_auto"] = ["-2,3-20", "-1,2-10"]


def _mut_fast_fake(fam: dict) -> None:
    fam["ipv6_extra"] = FAST_FOOLINGS_IPV6


_SCAN_MUTATORS: dict[str, dict[str, Callable[[dict], None]]] = {
    "full": {
        "fake": _mut_full_fake,
        "hostfake": _mut_full_tcp_fools,
        "fakedsplit": _mut_full_tcp_fools,
        "fakeddisorder": _mut_full_tcp_fools,
        "fake_hostfake": _mut_full_tcp_fools,
        "http_fake": _mut_full_tcp_fools,
        "quic_fake": _mut_full_quic_fake,
        "udp_discord": _mut_full_udp_discord,
    },
    "fast": {"fake": _mut_fast_fake},
}


def _apply_triage_axes(fam: dict, triage, scan_level: str, protocol: str = "tcp") -> None:
    from blockchecks.engine.blob_filter import filter_blob_aliases
    from blockchecks.engine.family_registry import (
        filter_fooling_values,
        filter_split_positions,
        filter_ttl_values,
    )

    if fam.get("foolings") is not None:
        fam["foolings"] = filter_fooling_values(fam["foolings"], triage)
    if fam.get("blobs") is not None:
        fam["blobs"] = filter_blob_aliases(fam["blobs"], triage, protocol=protocol)
    if fam.get("ttl_static") is not None:
        fam["ttl_static"] = filter_ttl_values(fam["ttl_static"], triage, scan_level=scan_level)
    if fam.get("positions") is not None:
        fam["positions"] = filter_split_positions(fam["positions"], triage, scan_level=scan_level)
    if triage.viable_hosts:
        fam["hosts"] = list(dict.fromkeys(triage.viable_hosts))[:8]
    if fam.get("ttl_auto") is not None and triage.autottl_delta is not None:
        fam["ttl_auto"] = list(dict.fromkeys([str(triage.autottl_delta), *fam["ttl_auto"]]))


# Standard Generator (parameterized strategy families)


class StandardGenerator(
    FakeFamiliesMixin, SplitFamiliesMixin, TamperFamiliesMixin, StrategyGenerator
):
    """Cover ALL standard blockcheck2.sh test scripts via parameterized families.

    Each family defines parameter axes. generate() iterates families
    and computes the Cartesian product of their axes.

    Usage:
      gen = StandardGenerator(strategy_types=["fake","hostfake"])
      # or: gen = StandardGenerator(strategy_types=["all"])
    """

    STRATEGY_FAMILIES: Mapping[str, Mapping[str, object]] = MappingProxyType(
        {s.name: s.axes for s in _family_spec.REGISTRY}
    )

    def __init__(self, strategy_types: list[str] | None = None):
        self.strategy_types = list(TCP_FAMILIES) if strategy_types is None else strategy_types
        for t in self.strategy_types:
            resolved = _resolve_family_name(t)
            if resolved not in _family_spec.BY_NAME and t != "all":
                raise ValueError(f"Unknown strategy type: {t}")

    async def generate(
        self,
        protocol: str = "tls12",
        state_db: RunStateStore = None,
        domain: str = "",
        scan_level: str = "fast",
        max_count: int = 500,
        run_set: set = None,
        triage: "TriageProfile | None" = None,
    ) -> list[StrategyItem]:
        """Generate strategies from specified families, gated by protocol.

        ``triage`` (optional) prunes provably useless branches:
        - unbypassable L3/IP block → empty (desync cannot help).
        - post-quantum ClientHello → keep contextual split markers, drop static
          numeric ``pos=N`` splits (2 TCP segments → marker-based only).
        - TLS fingerprint-blocked → prefer impersonation-friendly families.
        """
        if triage is not None and not triage.bypassable:
            return []

        def _prune(items_in: list[StrategyItem]) -> list[StrategyItem]:
            from blockchecks.engine.family_registry import prune_items_by_triage

            return prune_items_by_triage(items_in, triage, scan_level=scan_level)

        known_working = set(run_set or [])
        if state_db and domain and not known_working:
            known_working = set(await state_db.get_working_tcp(domain))

        raw = (
            list(_family_spec.BY_NAME)
            if "all" in self.strategy_types
            else list(self.strategy_types)
        )
        allowed = set(_FAMILIES_BY_PROTOCOL.get(protocol, TCP_FAMILIES))
        types = list(dict.fromkeys(r for t in raw if (r := _resolve_family_name(t)) in allowed))

        if triage is not None and scan_level != "full":
            from blockchecks.engine.family_registry import families_for_profile

            rec = set(families_for_profile(triage))
            if narrowed := [t for t in types if t in rec]:
                types = narrowed

        prepared: dict[str, dict] = {}
        for stype in types:
            if stype not in _family_spec.BY_NAME:
                continue
            fam = dict(axes_for(stype))
            if mut := _SCAN_MUTATORS.get(scan_level, {}).get(stype):
                mut(fam)
            if triage is not None:
                _apply_triage_axes(fam, triage, scan_level, protocol=protocol)
            prepared[stype] = fam

        expanded = {
            t: self._expand_family(t, prepared[t], scan_level, known_working)
            for t in types
            if t in prepared
        }
        flat = [it for t in types if t in expanded for it in expanded[t]]
        if len(flat) > max_count:
            return _prune(_round_robin(expanded, max_count))
        return _prune(flat[:max_count])

    _FAMILY_EXPANDERS = FAMILY_EXPANDERS

    def _expand_family(
        self, stype: str, family: dict, scan_level: str, known_working: set
    ) -> list[StrategyItem]:
        """Expand one strategy family into items."""
        expander_name = self._FAMILY_EXPANDERS.get(_resolve_family_name(stype))
        if expander_name is None:
            return []
        return getattr(self, expander_name)([], set(), family, scan_level, known_working)

    @staticmethod
    def _add(
        items: list,
        seen: set,
        label: str,
        strategy: str,
        protocol: str = "tls12",
    ) -> None:
        """Dedup by strategy string."""
        key = strategy.strip()
        if key not in seen:
            seen.add(key)
            items.append(StrategyItem(label=label, strategy=strategy, protocol=protocol))


async def _std_families(types: list[str], protocol: str = "tls12", **kwargs) -> list[StrategyItem]:
    kwargs.setdefault("protocol", protocol)
    return await StandardGenerator(strategy_types=types).generate(**kwargs)


class FakeTcpGenerator(StrategyGenerator):
    """Delegate to StandardGenerator family ``fake``."""

    async def generate(self, protocol: str = "tls12", **kwargs):
        return await _std_families(["fake"], protocol, **kwargs)


class HostfakeTcpGenerator(StrategyGenerator):
    """Delegate to StandardGenerator family ``hostfake``."""

    async def generate(self, protocol: str = "tls12", **kwargs):
        return await _std_families(["hostfake"], protocol, **kwargs)


class FakedTcpGenerator(StrategyGenerator):
    """Delegate to StandardGenerator families ``fakedsplit`` + ``fakeddisorder``."""

    async def generate(self, protocol: str = "tls12", **kwargs):
        return await _std_families(["fakedsplit", "fakeddisorder"], protocol, **kwargs)


class FakeMultiGenerator(StrategyGenerator):
    """Delegate to StandardGenerator family ``multi_fake``."""

    async def generate(self, protocol: str = "tls12", **kwargs):
        return await _std_families(["multi_fake"], protocol, **kwargs)


class FakeSplitComboGenerator(StrategyGenerator):
    """Delegate to StandardGenerator family ``fake_fakedsplit``."""

    async def generate(self, protocol: str = "tls12", **kwargs):
        return await _std_families(["fake_fakedsplit"], protocol, **kwargs)
