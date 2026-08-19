"""Standard hardcoded generators (blockcheck2.d/standard replicas).

Facade over the family-expansion modules in ``families/`` (split/fake/tamper).
Keeps the public generator classes + constants for back-compat.
"""

from typing import TYPE_CHECKING

from blockchecks.engine.generators.base import StrategyGenerator, StrategyItem
from blockchecks.engine.generators.families import (
    FakeFamiliesMixin,
    SplitFamiliesMixin,
    TamperFamiliesMixin,
)
from blockchecks.engine.generators.families._helpers import (
    _blob_abs,  # noqa: F401  (re-exported for back-compat)
    _blob_file,  # noqa: F401
    _fooling_clause,
    _static_numeric_split,
    _ttl_clause,
    _with_ack_drop,  # noqa: F401
    _with_ip6_send_drop,  # noqa: F401
    _with_send_md5,  # noqa: F401
)
from blockchecks.engine.store import RunStateStore

if TYPE_CHECKING:
    from blockchecks.engine.triage import TriageProfile

# Fooling options mapped from def.inc
FOOLINGS_TCP = [
    "tcp_ts=-1000",
    "",
    "tcp_md5",
    "tcp_ack=-66000:tcp_ts_up",
]
REPEATS_VALUES = [6, 3, 1, 8, 10, 11, 12, 2, 4]  # 6,8; 2,11 Flowseal; 4 matrix gap
TTL_VALUES = [1, 5, 7, 12, 63, 64, 127, 128, 255]
AUTOTTL_RANGES = ["-1,3-20", "-2,5-15", "-3,7-12"]

# Common blobs
# Common blobs (empty = auto-generated, not recommended)
BLOBS_TCP = ["stun", "max_ru", "google"]  # skipping empty — doesn't work on some ISPs
BLOBS_UDP = ["discord_udp"]


class FakeTcpGenerator(StrategyGenerator):
    """fake + blob + fooling + TTL + repeats combinations."""

    async def generate(
        self,
        protocol: str = "tls12",
        state_db: RunStateStore = None,
        domain: str = "",
        scan_level: str = "fast",
        max_count: int = 100,
        run_set: set = None,
    ) -> list[StrategyItem]:
        items = []
        known_working = list(run_set or [])

        if state_db and domain and not known_working:
            known_working = await state_db.get_working_tcp(domain)

        # In-run set: gets updated with PASS labels during the scan
        for blob in BLOBS_TCP:
            blob_part = f":blob={blob}" if blob else ""
            for repeats in REPEATS_VALUES:
                for fool in FOOLINGS_TCP:
                    fool_part = _fooling_clause(fool)
                    # Base strategy (no TTL) — test first
                    strat = f"fake{blob_part}:repeats={repeats}{fool_part}"
                    label = f"fake_{blob or 'none'}_r{repeats}_{fool or 'nofool'}"
                    items.append(StrategyItem(label=label, strategy=strat))
                    if scan_level == "single":
                        return items[:max_count]
                    if len(items) >= max_count:
                        return items[:max_count]

                    # fast: skip TTL only if base already PASSES (in-run or DB)
                    if scan_level == "fast":
                        skip = label in known_working
                        if not skip and state_db and domain:
                            # Check DB as fallback
                            skip = label in await state_db.get_working_tcp(domain)
                        if skip:
                            continue
                    if scan_level == "single":
                        continue

                    for ttl in TTL_VALUES + AUTOTTL_RANGES:
                        ttl_part = _ttl_clause(str(ttl))
                        if not ttl_part:
                            continue
                        strat_ttl = f"fake{blob_part}:repeats={repeats}{fool_part}{ttl_part}"
                        label_ttl = f"{label}_ttl{ttl}"
                        items.append(StrategyItem(label=label_ttl, strategy=strat_ttl))
                        if len(items) >= max_count:
                            return items[:max_count]

        return items[:max_count]


class HostfakeTcpGenerator(StrategyGenerator):
    """hostfakesplit + fooling + TTL + repeats."""

    async def generate(
        self,
        protocol: str = "tls12",
        state_db: RunStateStore = None,
        domain: str = "",
        scan_level: str = "fast",
        max_count: int = 100,
        run_set: set = None,
    ) -> list[StrategyItem]:
        items = []
        known_working = list(run_set or [])
        if state_db and domain:
            known_working = await state_db.get_working_tcp(domain)

        for fool in ["", "tcp_md5", "tcp_ts=-1000", "tcp_ack=-66000:tcp_ts_up"]:
            fool_part = _fooling_clause(fool)
            # Base
            strat = f"hostfakesplit:nofake2{fool_part}:repeats=1"
            label = f"hf_nofake2_{fool or 'nofool'}"
            items.append(StrategyItem(label=label, strategy=strat))
            if scan_level == "single":
                return items[:max_count]

            # fast: skip expansions only if base PASSES
            if scan_level == "fast":
                skip = label in known_working
                if not skip and state_db and domain:
                    skip = label in await state_db.get_working_tcp(domain)
                if skip:
                    continue
            if scan_level == "single":
                continue

            # With disorder_after
            strat2 = f"hostfakesplit:disorder_after:nofake2{fool_part}:repeats=1"
            label2 = f"hf_disorder_{fool or 'nofool'}"
            items.append(StrategyItem(label=label2, strategy=strat2))

            for ttl in TTL_VALUES + AUTOTTL_RANGES:
                ttl_part = _ttl_clause(str(ttl))
                if not ttl_part:
                    continue
                strat_ttl = f"hostfakesplit:nofake2{fool_part}:repeats=1{ttl_part}"
                label_ttl = f"{label}_ttl{ttl}"
                items.append(StrategyItem(label=label_ttl, strategy=strat_ttl))
                if len(items) >= max_count:
                    return items[:max_count]

        return items[:max_count]


class FakedTcpGenerator(StrategyGenerator):
    """fakedsplit / fakeddisorder — blockcheck2 30-faked.sh (M9)."""

    _SPLIT_FNS = ("fakedsplit", "fakeddisorder")
    _POSITIONS = [1, "midsld", "sniext+1", "method+2"]
    _PATTERNS = ["stun", "max_ru", "google", "4pda"]

    async def generate(
        self,
        protocol: str = "tls12",
        state_db: RunStateStore = None,
        domain: str = "",
        scan_level: str = "fast",
        max_count: int = 100,
        run_set: set = None,
    ) -> list[StrategyItem]:
        items = []
        for splitfn in self._SPLIT_FNS:
            for pos in self._POSITIONS:
                for pattern in self._PATTERNS:
                    for fool in ["", "tcp_md5", "tcp_ts=-1000"]:
                        fool_part = _fooling_clause(fool)
                        strat = f"{splitfn}:pos={pos}:pattern={pattern}{fool_part}"
                        label = f"{splitfn}_p{pos}_{pattern}_{fool or 'nofool'}"
                        items.append(StrategyItem(label=label, strategy=strat))
                        if scan_level == "single":
                            return items[:max_count]
                        if len(items) >= max_count:
                            return items[:max_count]
        return items[:max_count]


class FakeMultiGenerator(StrategyGenerator):
    """Multi-blob fake (2-3 blobs simultaneously)."""

    async def generate(
        self,
        protocol: str = "tls12",
        state_db: RunStateStore = None,
        domain: str = "",
        scan_level: str = "fast",
        max_count: int = 100,
        run_set: set = None,
    ) -> list[StrategyItem]:
        items = []
        blob_pairs = [
            ("stun", "max_ru"),
            ("max_ru", "stun"),
            ("stun", "google"),
            ("google", "stun"),
            ("max_ru", "google"),
            ("google", "max_ru"),
        ]
        for r1, r2 in [(6, 6), (6, 3), (3, 6)]:
            for fool in ["tcp_ts=-1000", ""]:
                fool_part = _fooling_clause(fool)
                for b1, b2 in blob_pairs:
                    strat = (
                        f"fake:blob={b1}:repeats={r1}{fool_part}\n"
                        f"fake:blob={b2}:repeats={r2}{fool_part}"
                    )
                    label = f"fake_multi_{b1}+{b2}_r{r1}+{r2}_{fool or 'nofool'}"
                    items.append(StrategyItem(label=label, strategy=strat))
                    if scan_level == "single":
                        return items[:max_count]
                    if len(items) >= max_count:
                        return items[:max_count]
        return items[:max_count]


class FakeSplitComboGenerator(StrategyGenerator):
    """fake + fakedsplit combined (blockcheck2 55-fake-faked.sh, M9)."""

    _POSITIONS = ["1", "midsld", "method+2"]
    _PATTERNS = ["stun", "max_ru", "google"]

    async def generate(
        self,
        protocol: str = "tls12",
        state_db: RunStateStore = None,
        domain: str = "",
        scan_level: str = "fast",
        max_count: int = 100,
        run_set: set = None,
    ) -> list[StrategyItem]:
        items = []
        for r in [6, 3, 8]:
            for fool in ["", "tcp_ts=-1000", "tcp_md5"]:
                fool_part = _fooling_clause(fool)
                for blob in ["stun", "max_ru", "google", ""]:
                    blob_part = f":blob={blob}" if blob else ""
                    for pos in self._POSITIONS:
                        for pattern in self._PATTERNS:
                            strat = (
                                f"fake{blob_part}:repeats={r}{fool_part}\n"
                                f"fakedsplit:pos={pos}:pattern={pattern}{fool_part}"
                            )
                            label = (
                                f"fake+fakedsplit_{blob or 'none'}+{pattern}_"
                                f"p{pos}_r{r}_{fool or 'nofool'}"
                            )
                            items.append(StrategyItem(label=label, strategy=strat))
                            if scan_level == "single":
                                return items[:max_count]
                            if len(items) >= max_count:
                                return items[:max_count]
        return items[:max_count]


# ── Extended parameters (from blockcheck.sh def.inc + standard scripts) ──

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
ALL_TTL = [1, 5, 7, 12, 63, 64, 127, 128, 255, 256, 512]  # >255 = out-of-range fooling wrap/cast
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

# All TCP blobs (extended from Flowseal) + null TLS blob from BC2 25-fake.sh
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
UDP_VOICE_FAMILIES = ["udp_discord"]
QUIC_HTTP3_FAMILIES = ["quic_fake", "quic_gv", "quic_ipfrag", "udp_quic", "udp_multiblob"]
UDP_QUIC_FAMILIES = ["udp_quic", "udp_game", "udp_multiblob"]
FAMILY_ALIASES = {"ipfrag_tcp": "tcp_ipfrag", "ipfrag_udp": "quic_ipfrag"}
_FAMILIES_BY_PROTOCOL = {
    "udp_voice": UDP_VOICE_FAMILIES,
    "udp_game": ["udp_game"],
    "http": HTTP_FAMILIES,
    "quic": QUIC_HTTP3_FAMILIES,
}


def _resolve_family_name(name: str) -> str:
    return FAMILY_ALIASES.get(name, name)


# ── Standard Generator (parameterized strategy families) ──


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

    # ── Strategy families ────────────────────────────────

    STRATEGY_FAMILIES = {
        # 25-fake.sh: fake + blob + fooling + TTL + TLS mod
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
            "foolings": FAST_FOOLINGS_TCP[:5],
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
        # M3: multidisorder (sonicdpi tier-1, blockcheck2 20-multi.sh)
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
        # M5: three-blob order subset (stun, max_ru, google permutations)
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
        # M1: fake + multisplit seqovl_pattern (blockcheck2 50-fake-multi / 55-fake-faked)
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
        # M2: fake + multisplit + hostfakesplit triple chain (ALT12)
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
        # M3: fake + multidisorder combo (blockcheck2 50-fake-multi.sh)
        "fake_multidisorder": {
            "blobs": ALL_BLOBS_TCP,
            "positions": ["1", "2", "midsld", "method+2"],
            "repeats": [6, 3, 8, 11],
            "foolings": ["tcp_ts=-1000", "tcp_md5", "badsum", ""],
        },
        # M3: fakedsplit / fakeddisorder (blockcheck2 30-faked.sh)
        "fakedsplit": {
            "positions": ["1", "midsld", "sniext+1", "method+2"],
            "pattern_blobs": ALL_BLOBS_TCP,
            "foolings": FAST_FOOLINGS_TCP[:4],
            "repeats": [6, 11],
            "ack_drop": True,
            "send_md5": True,
        },
        "fakeddisorder": {
            "positions": ["1", "midsld", "method+2", "1,midsld"],
            "pattern_blobs": ALL_BLOBS_TCP,
            "foolings": FAST_FOOLINGS_TCP[:4],
            "repeats": [6, 11],
            "ack_drop": True,
            "send_md5": True,
        },
        "fake_fakedsplit": {
            "blobs": ALL_BLOBS_TCP,
            "positions": ["1", "midsld", "method+2"],
            "pattern_blobs": ALL_BLOBS_TCP,
            "repeats": [6, 3, 8],
            "foolings": ["tcp_ts=-1000", "tcp_md5", "badsum", ""],
        },
        # Phase 7: TCP ipfrag (complement to quic_ipfrag)
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
        # Geneva 10-15: ACK → RST / RA duplicate (China 80-95%) on empty ACK
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
            # Geneva 16-18: exotic flag-fakes on the duplicated packet (send)
            "flag_fakes": [
                "send:tcp_flags_set=FIN,RST,ACK,PSH,URG,ECE:badsum",  # ≈ FRAPUEN
                "send:tcp_flags_set=FIN,RST,ECE,ACK,CWR:ip_ttl=10",  # ≈ FREACN
                "send:tcp_flags_set=FIN,RST,ACK,PSH,URG:tcp_md5",  # ≈ FRAPUN
                "send:tcp_flags_set=FIN:tcp_md5",  # F + md5 (Geneva 22-part)
            ],
        },
        # Geneva 23: SYN → SYN+ACK split handshake (KZ/IN 100%)
        # note: syn|synack (two-packet) omitted — '|' breaks nfqws2 conf splitter
        "synack": {
            "modes": ["synack", "synack", "acksyn"],
            "foolings": ["", "badsum", "ip_ttl=10"],
        },
        # blockcheck2 20/25/30/35/50: wssize companion (wsize=1:scale=6)
        "wssize": {
            "sizes": ["wssize:wsize=1:scale=6"],
            "combos": [False, True],  # True = paired with multisplit
        },
        # Geneva 1-9/22/24 escape-hatch: requires lua/blockchecks/geneva.lua
        # staged via BLOCKCHECKS_LUA_EXTRA=geneva.lua (custom fool= functions).
        "geneva_fool": {
            "fools": [
                "fool=bs_dataofs:badsum",
                "fool=bs_dataofs:ip_ttl=10",
                "fool=bs_iplen=64",
                "fool=bs_iplen=78",
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
                "quic_initial_www_google_com",
                "quic_initial_dbankcloud_ru",
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
        # M7: dual L7 UDP profile (stun + discord voice blob)
        "udp_multiblob": {
            "profiles": [
                ("stun", "discord_udp"),
                ("quic_dbank", "discord_udp"),
                ("game_udp", "discord_udp"),
            ],
            "repeats": [6, 10, 12],
        },
        # 25-fake.sh pktws_check_http — port 80, payload=http_req
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
        # M6: HTTP :80 fake (TLS side in composite preset / pair)
        "http_tls_dual": {
            "http_blobs": ["fake_default_http"],
            "repeats": [6, 3],
            "foolings": ["tcp_ts=-1000", "badsum", ""],
        },
        # 90-quic.sh — HTTP/3 over UDP/443
        "quic_fake": {
            "blobs": ["fake_default_quic", "quic_initial", "quic_google", "quic_vk"],
            "repeats": [1, 2, 5, 6, 10, 11, 20],
            "foolings": ["", "badsum"],
            "ip6_send_drop": True,
        },
        # GV-5: googlevideo CDN QUIC kyber blobs (HTTP/3 probe)
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
            if triage is None:
                return items_in
            # Post-quantum ClientHello (2 TCP segments) → static numeric splits
            # land mid-record; keep only contextual markers (sni/sniext).
            if triage.prefer_contextual_split and triage.requires_postquantum_awareness:
                return [it for it in items_in if not _static_numeric_split(it.strategy)]
            return items_in

        # (build happens below; both return paths apply _prune)
        items = []
        seen: set[str] = set()
        known_working = list(run_set or [])
        if state_db and domain and not known_working:
            known_working = await state_db.get_working_tcp(domain)

        types = list(self.strategy_types)
        if "all" in types:
            types = list(self.STRATEGY_FAMILIES.keys())

        # Protocol gate — empty intersection means nothing for this protocol
        allowed = _FAMILIES_BY_PROTOCOL.get(protocol, TCP_FAMILIES)
        types = [t for t in types if _resolve_family_name(t) in allowed]

        # Expand axes for full scan
        full = scan_level == "full"
        n_types = max(1, len(types))

        prepared: dict[str, dict] = {}
        for stype in types:
            resolved = _resolve_family_name(stype)
            family = self.STRATEGY_FAMILIES.get(resolved)
            if not family:
                continue
            fam = dict(family)
            if full and resolved == "fake":
                fam["repeats"] = [r for r in ALL_REPEATS if r not in (100, 260)]
                fam["foolings"] = ALL_FOOLINGS_TCP + ALL_FOOLINGS_IPV6
                fam["tls_mods"] = TLS_MODS
            elif full and resolved in (
                "hostfake",
                "fakedsplit",
                "fakeddisorder",
                "fake_hostfake",
                "http_fake",
            ):
                fam["foolings"] = list(
                    dict.fromkeys(list(fam.get("foolings", [])) + ALL_FOOLINGS_TCP)
                )
            elif full and resolved == "quic_fake":
                fam["foolings"] = list(
                    dict.fromkeys(list(fam.get("foolings", [""])) + ALL_FOOLINGS_UDP)
                )
                fam["ip6_fools"] = ALL_FOOLINGS_IPV6
            elif full and resolved == "udp_discord":
                fam["repeats"] = [2, 3, 4, 6, 8, 10, 12, 14]
                fam["ttl_static"] = [5, 8]
                fam["ttl_auto"] = ["-2,3-20", "-1,2-10"]
            elif scan_level == "fast" and resolved == "fake":
                # Limited IPv6 fooling axis on fast
                fam["ipv6_extra"] = FAST_FOOLINGS_IPV6
            prepared[resolved] = fam

        for idx, stype in enumerate(types):
            resolved = _resolve_family_name(stype)
            fam = prepared.get(resolved)
            if not fam:
                continue
            room = max_count - len(items)
            if room <= 0:
                break
            remaining_types = n_types - idx
            if full:
                # Full scan: no per-type budget sharing — emit everything, then
                # truncate by max_count. Equal shares would starve large
                # families (fake 18k) when small ones (synack 6) join the pool.
                share = room
            else:
                share = max(1, room // remaining_types)
            new = self._expand_family(resolved, fam, scan_level, seen, known_working)
            items.extend(new[:share])

        # Capped scan (any scan_level): interleave one strategy per family
        # round-robin so every technique (incl. new rst_fake/synack/
        # geneva_fool/wssize) is represented instead of letting the first
        # family eat the budget. Full pool is emitted when max_count allows.
        expanded = {
            t: self._expand_family(t, dict(prepared[t]), scan_level, set(), known_working)
            for t in types
            if t in prepared
        }
        if sum(len(v) for v in expanded.values()) > max_count:
            out: list[StrategyItem] = []
            seen_out: set[str] = set()
            idx = 0
            while len(out) < max_count:
                advanced = False
                for t in types:
                    lst = expanded.get(t, [])
                    if idx < len(lst):
                        it = lst[idx]
                        if it.strategy not in seen_out:
                            seen_out.add(it.strategy)
                            out.append(it)
                        advanced = True
                if not advanced:
                    break
                idx += 1
            return _prune(out[:max_count])

        return _prune(items[:max_count])

    # Aliases for todo / CLI naming (ipfrag_tcp / ipfrag_udp)
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
        "ipfrag_tcp": "_fam_tcp_ipfrag",
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
        "ipfrag_udp": "_fam_quic_ipfrag",
    }

    def _expand_family(
        self, stype: str, family: dict, scan_level: str, seen: set, known_working: list
    ) -> list[StrategyItem]:
        """Expand one strategy family into items."""
        items: list[StrategyItem] = []
        seen_local: set[str] = set()

        expander_name = self._FAMILY_EXPANDERS.get(stype)
        if expander_name is None:
            return items
        return getattr(self, expander_name)(items, seen_local, family, scan_level, known_working)

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
