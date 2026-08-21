"""Standard nfqws2 strategy families. Facade over families/split, fake, and tamper."""

from collections.abc import Callable
from typing import TYPE_CHECKING

from blockchecks.engine.generators.base import StrategyGenerator, StrategyItem
from blockchecks.engine.generators.families import (
    FakeFamiliesMixin,
    SplitFamiliesMixin,
    TamperFamiliesMixin,
)
from blockchecks.engine.store import RunStateStore

if TYPE_CHECKING:
    from blockchecks.engine.triage import TriageProfile

# Extended parameters (from blockcheck.sh def.inc + standard scripts)

# Full foolings matching blockcheck2.sh def.inc FOOLINGS46_TCP
ALL_FOOLINGS_TCP = [
    "",
    "tcp_md5",
    "badsum",
    "tcp_seq=-3000",
    "tcp_seq=1000000",
    "tcp_ack=-66000:tcp_ts_up",
    "tcp_ts=-1000",
    "tcp_flags_unset=ACK",
    "tcp_flags_set=SYN",
]
ALL_FOOLINGS_UDP = ["badsum"]
# FOOLINGS6_TCP / FOOLINGS6_UDP from def.inc
ALL_FOOLINGS_IPV6 = [
    "ip6_hopbyhop",
    "ip6_hopbyhop:ip6_hopbyhop2",
    "ip6_destopt",
    "ip6_routing",
    "ip6_ah",
]
FAST_FOOLINGS_IPV6 = ["ip6_hopbyhop", "ip6_destopt"]

# Extended repeats, TTL
ALL_REPEATS = [6, 3, 1, 8, 10, 11, 12, 2, 4, 5, 7, 9, 14, 15, 20]  # 100,260 only for tcpseg
ALL_TTL = [1, 5, 7, 12, 63, 64, 127, 128, 255]  # zapret2 ttl_discover: 0 <= ttl <= 255
ALL_AUTOTTL = ["-1,3-20", "-2,5-15", "-3,7-12", "-4,3-20", "-5,5-15"]

# All split positions from blockcheck2.sh
ALL_SPLIT_POSITIONS = [
    "1",
    "2",
    "3",
    "23",
    "45",
    "midsld",
    "sniext+1",
    "sniext+4",
    "host+1",
    "1,midsld",
    "1,midsld,1220",
    "1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1",
]
# Sequence overlap values (Flowseal variants)
ALL_SEQOVL = [1, 568, 652, 664, 679, 681]

# TLS modification flags (from blockcheck2.sh standard scripts)
TLS_MODS = [
    "",  # no mod
    "rnd",  # randomize extensions
    "rnd,dupsid",  # + duplicate session ID
    "rnd,dupsid,padencap",  # + pad encapsulation
    "rnd,dupsid,sni=www.google.com",  # + SNI substitution
    "rnd,dupsid,sni=fonts.google.com",
    "rnd,dupsid,sni=ya.ru",
]

# TCP blobs plus a null TLS blob (first, so a capped --max still hits it)
# Null blob first so capped --max scans still exercise it
ALL_BLOBS_TCP = ["0x00000000", "stun", "max_ru", "google", "4pda"]

# Foolings for fast/default scans (flags + full seq only in full)
# Geneva flag/seq fools (tcp_flags_set/unset, tcp_seq, tcp_ack) promoted to fast
FAST_FOOLINGS_TCP = [
    "tcp_ts=-1000",
    "",
    "tcp_md5",
    "badsum",
    "tcp_ack=-66000:tcp_ts_up",
    "tcp_md5:tcp_ts=-1000",
    "tcp_seq=-3000",
    "tcp_seq=1000000",
    "tcp_flags_unset=ACK",
    "tcp_flags_set=SYN",
]
FAST_REPEATS = [6, 8, 3, 11, 12, 4, 14]


TCP_FAMILIES = [
    "fake",
    "rst_fake",
    "synack",
    "geneva_fool",
    "wssize",
    "hostfake",
    "multisplit",
    "multidisorder",
    "syndata",
    "tcpseg",
    "oob",
    "multi_fake",
    "triple_fake",
    "fake_multisplit",
    "fake_multidisorder",
    "fake_multisplit_hostfake",
    "fake_hostfake",
    "fakedsplit",
    "fakeddisorder",
    "fake_fakedsplit",
    "tcp_ipfrag",
]
HTTP_FAMILIES = ["http_simple", "http_fake", "http_tls_dual"]
UDP_VOICE_FAMILIES = ["udp_discord", "udp_multiblob"]
QUIC_HTTP3_FAMILIES = ["quic_fake", "quic_gv", "quic_ipfrag", "udp_quic"]
UDP_QUIC_FAMILIES = ["udp_quic", "udp_game"]
FAMILY_ALIASES = {"ipfrag_tcp": "tcp_ipfrag", "ipfrag_udp": "quic_ipfrag"}
_FAMILIES_BY_PROTOCOL = {
    "udp_voice": UDP_VOICE_FAMILIES,
    "udp_game": ["udp_game"],
    "http": HTTP_FAMILIES,
    "quic": QUIC_HTTP3_FAMILIES,
}


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


def _apply_triage_axes(fam: dict, triage, scan_level: str) -> None:
    from blockchecks.engine.blob_filter import filter_blob_aliases
    from blockchecks.engine.family_registry import (
        filter_fooling_values,
        filter_split_positions,
        filter_ttl_values,
    )

    if fam.get("foolings") is not None:
        fam["foolings"] = filter_fooling_values(fam["foolings"], triage)
    if fam.get("blobs") is not None:
        fam["blobs"] = filter_blob_aliases(fam["blobs"], triage)
    if fam.get("ttl_static") is not None:
        fam["ttl_static"] = filter_ttl_values(fam["ttl_static"], triage, scan_level=scan_level)
    if fam.get("positions") is not None:
        fam["positions"] = filter_split_positions(fam["positions"], triage, scan_level=scan_level)
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

    # Strategy families

    STRATEGY_FAMILIES = {
        # fake + blob + fooling + TTL + TLS mod
        "fake": {
            "blobs": ALL_BLOBS_TCP,
            "repeats": FAST_REPEATS,
            "foolings": FAST_FOOLINGS_TCP,
            "ttl_static": ALL_TTL,
            "ttl_auto": ALL_AUTOTTL,
            "tls_mods": TLS_MODS[:3],
            "ack_drop": True,
            "send_md5": True,
        },
        "hostfake": {
            "foolings": [f for f in FAST_FOOLINGS_TCP[:5] if f],
            "variants": ["base", "disorder", "nofake1", "midhost=midsld", "nodrop"],
            "ttl_static": ALL_TTL,
            "ttl_auto": ALL_AUTOTTL,
            "ack_drop": True,
            "send_md5": True,
        },
        "multisplit": {
            "repeats": [1, 6, 11],
            "positions": ALL_SPLIT_POSITIONS,
            "foolings": FAST_FOOLINGS_TCP[:4],
            "seqovl": ALL_SEQOVL,
            "seqovl_blobs": ALL_BLOBS_TCP,
            "ttl_static": ALL_TTL,
            "ttl_auto": ALL_AUTOTTL,
            "padencap": True,
        },
        # multidisorder
        "multidisorder": {
            "positions": ["1", "2", "midsld", "method+2", "1,midsld"],
            "foolings": FAST_FOOLINGS_TCP[:4],
            "seqovl": [664, 681],
            "seqovl_blobs": ALL_BLOBS_TCP,
            "padencap": True,
        },
        "syndata": {
            "blobs": ["0x1603", "fake_default_tls", ""],
            "tls_mods": ["", "rnd,dupsid", "rnd,dupsid,sni=www.google.com"],
            "plus_split": [False, True],
            "plus_hostfake": True,
        },
        "tcpseg": {
            "positions": ["0,1", "0,midsld"],
            "repeats": [1, 20, 100, 260],
            "ip_id": "rnd",
        },
        "oob": {
            "urps": ["b", "0", "2", "midsld"],
            "in_range": "-s1",
        },
        "multi_fake": {
            "blob_pairs": [
                ("stun", "max_ru"),
                ("max_ru", "stun"),
                ("stun", "google"),
                ("google", "stun"),
                ("max_ru", "google"),
                ("google", "max_ru"),
                ("stun", "4pda"),
                ("4pda", "stun"),
            ],
            "repeat_pairs": [(6, 6), (6, 3), (8, 6), (3, 6)],
            "foolings": ["tcp_ts=-1000", "tcp_md5", "badsum", ""],
        },
        # Three-blob orders: stun, max_ru, google
        "triple_fake": {
            "triples": [
                ("stun", "max_ru", "google"),
                ("stun", "google", "max_ru"),
                ("max_ru", "stun", "google"),
                ("google", "stun", "max_ru"),
            ],
            "repeats": [6, 3],
            "foolings": ["tcp_ts=-1000", "badsum", ""],
        },
        # fake + multisplit seqovl_pattern
        "fake_multisplit": {
            "blob_pairs": [
                ("stun", "max_ru"),
                ("stun", "google"),
                ("max_ru", "google"),
                ("stun", "4pda"),
                ("google", "max_ru"),
                ("4pda", "google"),
            ],
            "pattern_blobs": ALL_BLOBS_TCP,
            "seqovl": [664, 681, 652],
            "positions": ["2", "1,midsld", "midsld"],
            "repeats": [6, 3, 8],
            "foolings": ["tcp_ts=-1000", "tcp_md5", "badsum", ""],
        },
        # fake + multisplit + hostfakesplit
        "fake_multisplit_hostfake": {
            "blob_pairs": [
                ("google", "max_ru"),
                ("stun", "max_ru"),
                ("stun", "google"),
                ("max_ru", "google"),
            ],
            "seqovl": [664, 681],
            "positions": ["1", "2"],
            "repeats": [6, 8],
            "foolings": ["tcp_ts=-1000", "tcp_md5", "badsum"],
            "hf_hosts": ["www.google.com", "fonts.google.com"],
        },
        # fake + multidisorder
        "fake_multidisorder": {
            "blobs": ALL_BLOBS_TCP,
            "positions": ["1", "2", "midsld", "method+2"],
            "repeats": [6, 3, 8, 11],
            "foolings": ["tcp_ts=-1000", "tcp_md5", "badsum", ""],
        },
        # fakedsplit / fakeddisorder
        "fakedsplit": {
            "positions": ["1", "midsld", "sniext+1", "method+2"],
            "pattern_blobs": ALL_BLOBS_TCP,
            "foolings": [f for f in FAST_FOOLINGS_TCP[:4] if f],
            "repeats": [6, 11],
            "ack_drop": True,
            "send_md5": True,
        },
        "fakeddisorder": {
            "positions": ["1", "midsld", "method+2"],
            "pattern_blobs": ALL_BLOBS_TCP,
            "foolings": [f for f in FAST_FOOLINGS_TCP[:4] if f],
            "repeats": [6, 11],
            "ack_drop": True,
            "send_md5": True,
        },
        "fake_fakedsplit": {
            "blobs": ALL_BLOBS_TCP,
            "positions": ["1", "midsld", "method+2"],
            "pattern_blobs": ALL_BLOBS_TCP,
            "repeats": [6, 3, 8],
            "foolings": ["tcp_ts=-1000", "tcp_md5", "badsum"],
        },
        # TCP ipfrag (beside quic_ipfrag)
        "tcp_ipfrag": {
            "positions": [8, 16, 24, 32, 40, 48, 64],
            "repeats": [6, 11, 4],
            "combo_blobs": ["", "stun", "google"],
            "disorder": [False, True],
            "ipfrag_next": [None, 255],
        },
        "fake_hostfake": {
            "blobs": ALL_BLOBS_TCP,
            "repeats": [6, 3, 8, 11, 2],
            "foolings": ["tcp_ts=-1000", "tcp_md5", "badsum"],
            "hf_variants": ["base", "disorder_after"],
            "ack_drop": True,
            "send_md5": True,
        },
        # Duplicate empty ACK as RST or RST+ACK
        "rst_fake": {
            "mods": [
                "rst:badsum",
                "rst:ip_ttl=10",
                "rst:ip_ttl=1",
                "rst:tcp_md5",
                "rst:rstack:badsum",
                "rst:rstack:ip_ttl=10",
                "rst:rstack:ip_ttl=1",
                "rst:badsum:tcp_md5",
            ],
            # Flag combinations on a duplicated packet (send)
            "flag_fakes": [
                "send:tcp_flags_set=FIN,RST,ACK,PSH,URG,ECE:badsum",  # ≈ FRAPUEN
                "send:tcp_flags_set=FIN,RST,ECE,ACK,CWR:ip_ttl=10",  # ≈ FREACN
                "send:tcp_flags_set=FIN,RST,ACK,PSH,URG:tcp_md5",  # ≈ FRAPUN
                "send:tcp_flags_set=FIN:tcp_md5",  # F + md5 (Geneva 22-part)
            ],
        },
        # SYN then SYN+ACK split handshake
        # note: syn|synack (two-packet) omitted — '|' breaks nfqws2 conf splitter
        "synack": {
            "modes": ["synack", "synack", "acksyn"],
            "foolings": [""],  # synack core does not support badsum / ip_ttl in zapret2
        },
        # blockcheck2 20/25/30/35/50: wssize companion (wsize=1:scale=6)
        "wssize": {
            "sizes": ["wssize:wsize=1:scale=6"],
            "combos": [False, True],  # True = paired with multisplit
        },
        # Custom fool= hooks from lua/blockchecks/geneva.lua (default lua chain).
        "geneva_fool": {
            "fools": [
                "fool=bs_dataofs:badsum",
                "fool=bs_dataofs:ip_ttl=10",
                "fool=bs_iplen:len=64",
                "fool=bs_iplen:len=78",
                "fool=bs_corrupt_load",
                "fool=bs_corrupt_load:badsum",
                "fool=bs_corrupt_load:ip_ttl=8",
                "fool=bs_corrupt_wscale",
                "fool=bs_corrupt_uto",
            ],
            "repeats": [1, 2],
        },
        # Voice UDP — lua-desync cores (list_udp_voice.txt parity)
        "udp_discord": {
            "blobs": ["discord_udp", "stun"],
            "repeats": [6, 12, 3, 2],
            "ttl_static": [5],
            "ttl_auto": ["-2,3-20"],
        },
        "udp_quic": {
            "port_ranges": ["443"],
            "blobs": [
                "quic_google",
                "quic_dbank",
                "quic_gv_kyber_1",
                "quic_gv_kyber_2",
            ],
            "repeats": [1, 2, 5, 6, 10, 11, 20],
        },
        "udp_game": {
            "port_ranges": ["1024-65535"],
            "blobs": ["quic_initial_dbankcloud_ru", "game_udp"],
            "repeats": [10, 12, 14],
            "out_range": [None, "n1-<n3", "n1-<n4", "n1-<n5"],
        },
        # UDP stun + discord voice blob
        "udp_multiblob": {
            "profiles": [
                ("stun", "discord_udp"),
                ("quic_dbank", "discord_udp"),
                ("game_udp", "discord_udp"),
            ],
            "repeats": [6, 10, 12],
        },
        # HTTP :80, payload=http_req
        "http_simple": {
            "variants": [
                "http_hostcase",
                "http_methodeol",
                "http_hostcase:spell=hoSt",
                "http_domcase",
                "http_unixeol",
            ],
        },
        "http_fake": {
            "blobs": ["fake_default_http", "0x00000000"],
            "repeats": FAST_REPEATS[:4],
            "foolings": FAST_FOOLINGS_TCP[:4],
        },
        # HTTP :80 fake
        "http_tls_dual": {
            "http_blobs": ["fake_default_http"],
            "repeats": [6, 3],
            "foolings": ["tcp_ts=-1000", "badsum", ""],
        },
        # HTTP/3 over UDP/443
        "quic_fake": {
            "blobs": ["fake_default_quic", "quic_initial", "quic_google", "quic_vk"],
            "repeats": [1, 2, 5, 6, 10, 11, 20],
            "foolings": ["", "badsum"],
            "ip6_send_drop": True,
        },
        # googlevideo CDN QUIC kyber blobs (HTTP/3)
        "quic_gv": {
            "blobs": ["quic_gv_kyber_1", "quic_gv_kyber_2", "quic_google"],
            "repeats": [1, 2, 5, 6, 11],
        },
        "quic_ipfrag": {
            "positions": [8, 16, 24, 32, 40, 48, 64],
            "repeats": [6, 11, 4],
            "disorder": [False, True],
            "ipfrag_next": [None, 255],
        },
    }

    def __init__(self, strategy_types: list[str] | None = None):
        self.strategy_types = strategy_types or list(TCP_FAMILIES)
        for t in self.strategy_types:
            resolved = _resolve_family_name(t)
            if resolved not in self.STRATEGY_FAMILIES and t != "all":
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
            list(self.STRATEGY_FAMILIES)
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
            family = self.STRATEGY_FAMILIES.get(stype)
            if not family:
                continue
            fam = dict(family)
            if mut := _SCAN_MUTATORS.get(scan_level, {}).get(stype):
                mut(fam)
            if triage is not None:
                _apply_triage_axes(fam, triage, scan_level)
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

    _FAMILY_EXPANDERS = {
        "fake": "_fam_fake",
        "hostfake": "_fam_hostfake",
        "multisplit": "_fam_multisplit",
        "multidisorder": "_fam_multidisorder",
        "syndata": "_fam_syndata",
        "tcpseg": "_fam_tcpseg",
        "oob": "_fam_oob",
        "multi_fake": "_fam_multi_fake",
        "triple_fake": "_fam_triple_fake",
        "fake_multisplit": "_fam_fake_multisplit",
        "fake_multisplit_hostfake": "_fam_fake_multisplit_hostfake",
        "fake_multidisorder": "_fam_fake_multidisorder",
        "fakedsplit": "_fam_fakedsplit",
        "fakeddisorder": "_fam_fakeddisorder",
        "fake_fakedsplit": "_fam_fake_fakedsplit",
        "tcp_ipfrag": "_fam_tcp_ipfrag",
        "fake_hostfake": "_fam_fake_hostfake",
        "rst_fake": "_fam_rst_fake",
        "synack": "_fam_synack",
        "wssize": "_fam_wssize",
        "geneva_fool": "_fam_geneva_fool",
        "udp_discord": "_fam_udp_discord",
        "udp_quic": "_fam_udp_quic",
        "udp_game": "_fam_udp_game",
        "udp_multiblob": "_fam_udp_multiblob",
        "http_simple": "_fam_http_simple",
        "http_fake": "_fam_http_fake",
        "http_tls_dual": "_fam_http_tls_dual",
        "quic_fake": "_fam_quic_fake",
        "quic_gv": "_fam_quic_gv",
        "quic_ipfrag": "_fam_quic_ipfrag",
    }

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
