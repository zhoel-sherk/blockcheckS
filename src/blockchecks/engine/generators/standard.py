"""Standard hardcoded generators (blockcheck2.d/standard replicas)."""

import os

from blockchecks.engine.blob_aliases import BLOB_ALIAS_MAP, resolve_blob_path
from blockchecks.engine.config import BLOB_DIR
from blockchecks.engine.generators.base import StrategyGenerator, StrategyItem
from blockchecks.engine.store import RunStateStore

# Fooling options mapped from def.inc
FOOLINGS_TCP = [
    "tcp_ts=-1000",
    "",
    "tcp_md5",
    "tcp_ack=-66000:tcp_ts_up",
]
REPEATS_VALUES = [6, 3, 1, 8, 10, 11, 12, 2]  # 6,8 working on Fryazino; 2,11 from Flowseal
TTL_VALUES = [1, 5, 7, 12, 63, 64, 127, 128, 255]
AUTOTTL_RANGES = ["-1,3-20", "-2,5-15", "-3,7-12"]

# Common blobs
# Common blobs (empty = auto-generated, not recommended)
BLOBS_TCP = ["stun", "max_ru", "google"]  # skipping empty — doesn't work on Fryazino
BLOBS_UDP = ["discord_udp"]


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
ALL_REPEATS = [6, 3, 1, 8, 10, 11, 12, 2, 5, 7, 9, 15, 20]  # 100,260 only for tcpseg
ALL_TTL = [1, 5, 7, 12, 63, 64, 127, 128, 255]  # 63=ttl_minus_1, boundary values for other ISPs
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
# Null blob early so capped --max scans still exercise it
ALL_BLOBS_TCP = ["stun", "0x00000000", "max_ru", "google", "4pda"]

# Foolings for fast/default scans (flags + full seq only in full)
FAST_FOOLINGS_TCP = [
    "tcp_ts=-1000",
    "",
    "tcp_md5",
    "badsum",
    "tcp_ack=-66000:tcp_ts_up",
    "tcp_md5:tcp_ts=-1000",
]
FAST_REPEATS = [6, 8, 3, 11, 12]


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


TCP_FAMILIES = [
    "fake",
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

# ── Standard Generator (parameterized strategy families) ──


class StandardGenerator(StrategyGenerator):
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
            "positions": [8, 16, 32, 64],
            "repeats": [6, 11],
            "combo_blobs": ["", "stun", "google"],
        },
        "fake_hostfake": {
            "blobs": ALL_BLOBS_TCP,
            "repeats": [6, 3, 8, 11, 2],
            "foolings": ["tcp_ts=-1000", "tcp_md5", "badsum"],
            "hf_variants": ["base", "disorder_after"],
            "ack_drop": True,
            "send_md5": True,
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
            "positions": [8, 16, 32, 64],
            "repeats": [6, 11],
        },
    }

    def __init__(self, strategy_types: list[str] | None = None):
        self.strategy_types = strategy_types or list(TCP_FAMILIES)
        for t in self.strategy_types:
            if t not in self.STRATEGY_FAMILIES and t != "all":
                raise ValueError(f"Unknown strategy type: {t}")

    async def generate(
        self,
        protocol: str = "tls12",
        state_db: RunStateStore = None,
        domain: str = "",
        scan_level: str = "fast",
        max_count: int = 500,
        run_set: set = None,
    ) -> list[StrategyItem]:
        """Generate strategies from specified families, gated by protocol."""
        items = []
        seen: set[str] = set()
        known_working = list(run_set or [])
        if state_db and domain and not known_working:
            known_working = await state_db.get_working_tcp(domain)

        types = list(self.strategy_types)
        if "all" in types:
            types = list(self.STRATEGY_FAMILIES.keys())

        # Protocol gate — empty intersection means nothing for this protocol
        if protocol == "udp_voice":
            types = [t for t in types if t in UDP_VOICE_FAMILIES]
        elif protocol == "http":
            types = [t for t in types if t in HTTP_FAMILIES]
        elif protocol == "quic":
            types = [t for t in types if t in QUIC_HTTP3_FAMILIES]
        else:
            # tls12/tls13 — TCP TLS only
            types = [t for t in types if t in TCP_FAMILIES]

        # Expand axes for full scan
        full = scan_level == "full"
        n_types = max(1, len(types))

        for idx, stype in enumerate(types):
            family = self.STRATEGY_FAMILIES.get(stype)
            if not family:
                continue
            fam = dict(family)
            if full and stype == "fake":
                fam["repeats"] = [r for r in ALL_REPEATS if r not in (100, 260)]
                fam["foolings"] = ALL_FOOLINGS_TCP + ALL_FOOLINGS_IPV6
                fam["tls_mods"] = TLS_MODS
            elif full and stype in (
                "hostfake",
                "fakedsplit",
                "fakeddisorder",
                "fake_hostfake",
                "http_fake",
            ):
                fam["foolings"] = list(
                    dict.fromkeys(list(fam.get("foolings", [])) + ALL_FOOLINGS_TCP)
                )
            elif full and stype == "quic_fake":
                fam["foolings"] = list(
                    dict.fromkeys(list(fam.get("foolings", [""])) + ALL_FOOLINGS_UDP)
                )
                fam["ip6_fools"] = ALL_FOOLINGS_IPV6
            elif scan_level == "fast" and stype == "fake":
                # Limited IPv6 fooling axis on fast
                fam["ipv6_extra"] = FAST_FOOLINGS_IPV6
            room = max_count - len(items)
            if room <= 0:
                break
            remaining_types = n_types - idx
            share = max(1, room // remaining_types)
            new = self._expand_family(stype, fam, scan_level, seen, known_working)
            items.extend(new[:share])

        return items[:max_count]

    def _expand_family(
        self, stype: str, family: dict, scan_level: str, seen: set, known_working: list
    ) -> list[StrategyItem]:
        """Expand one strategy family into items."""
        items = []
        seen: set[str] = set()

        if stype == "fake":
            # IPv6 samples before TTL explosion (skip on single — one strat per family)
            if scan_level != "single":
                for ip6 in family.get("ipv6_extra", []):
                    for blob_name in ("stun", "google"):
                        strat = f"fake:blob={blob_name}:repeats=6:{ip6}"
                        self._add(items, seen, f"std_fake_{blob_name}_r6_{ip6}", strat)
            for blob_name in family["blobs"]:
                blob = f":blob={blob_name}"
                for repeats in family["repeats"]:
                    for fool in family["foolings"]:
                        fool_str = f":{fool}" if fool else ""
                        # Base (no TTL)
                        strat = f"fake{blob}:repeats={repeats}{fool_str}"
                        label = f"std_fake_{blob_name}_r{repeats}_{fool or 'nofool'}"
                        self._add(items, seen, label, strat)

                        if scan_level == "single":
                            return items

                        # BC2 companions (bounded: top blobs + key foolings)
                        if family.get("ack_drop") and fool in ("", "tcp_ts=-1000") and blob_name in (
                            "stun",
                            "google",
                            "0x00000000",
                        ):
                            self._add(
                                items,
                                seen,
                                f"{label}_ackdrop",
                                _with_ack_drop(strat),
                            )
                        if family.get("send_md5") and "tcp_md5" in (fool or ""):
                            self._add(
                                items,
                                seen,
                                f"{label}_sendmd5",
                                _with_send_md5(strat),
                            )

                        # Skip TTL if base known-working
                        if scan_level == "fast" and label in known_working:
                            continue

                        # TTL variants
                        for ttl in family["ttl_static"]:
                            self._add(items, seen, f"{label}_ttl{ttl}", f"{strat}:ip_ttl={ttl}")
                        for ttl in family["ttl_auto"]:
                            self._add(
                                items, seen, f"{label}_autottl{ttl}", f"{strat}:ip_autottl={ttl}"
                            )
                        # TLS mods (google blob + full on padencap path)
                        if blob_name in ("google", "0x00000000") and not fool:
                            for tmod in family["tls_mods"]:
                                if not tmod:
                                    continue
                                for r in [6, 8]:
                                    s = f"fake:blob={blob_name}:repeats={r}:tls_mod={tmod}"
                                    self._add(
                                        items, seen, f"std_fake_{blob_name}_r{r}_tlsmod={tmod[:20]}", s
                                    )

        elif stype == "hostfake":
            for fool in family["foolings"]:
                fool_str = f":{fool}" if fool else ""
                for variant in family["variants"]:
                    if variant == "base":
                        core = f"hostfakesplit:nofake2{fool_str}:repeats=1"
                    elif variant == "disorder":
                        core = f"hostfakesplit:disorder_after:nofake2{fool_str}:repeats=1"
                    else:
                        core = f"hostfakesplit:{variant}{fool_str}:repeats=1"
                    label = f"std_hf_{variant}_{fool or 'nofool'}"
                    self._add(items, seen, label, core)
                    if scan_level == "single":
                        return items

                    if family.get("ack_drop") and fool in ("", "tcp_ts=-1000") and variant == "base":
                        self._add(items, seen, f"{label}_ackdrop", _with_ack_drop(core))
                    if family.get("send_md5") and "tcp_md5" in (fool or "") and variant == "base":
                        self._add(items, seen, f"{label}_sendmd5", _with_send_md5(core))

                    if scan_level == "fast" and label in known_working:
                        continue

                    for ttl in family["ttl_static"]:
                        self._add(items, seen, f"{label}_ttl{ttl}", f"{core}:ip_ttl={ttl}")
                    for ttl in family["ttl_auto"]:
                        self._add(items, seen, f"{label}_autottl{ttl}", f"{core}:ip_autottl={ttl}")

        elif stype == "multisplit":
            # Limit: most useful pos,seqovl pairs
            pos_seqovl_pairs = [
                ("1", 1),
                ("2", 652),
                ("midsld", 1),
                ("sniext+1", 679),
                ("1,midsld", 1),
                ("host+1", 681),
            ]
            for pos, seqovl in pos_seqovl_pairs:
                for fool in family["foolings"]:
                    fool_str = f":{fool}" if fool else ""
                    for blob_name in family["seqovl_blobs"]:
                        if blob_name == "0x00000000":
                            continue
                        strat = (
                            f"multisplit:pos={pos}:seqovl={seqovl}"
                            f":seqovl_pattern={blob_name}{fool_str}"
                        )
                        label = f"std_split_{pos}_s{seqovl}_{blob_name}_{fool or 'nofool'}"
                        self._add(items, seen, label, strat)
                        if scan_level == "single":
                            return items
                        for ttl in family["ttl_static"]:
                            self._add(items, seen, f"{label}_ttl{ttl}", f"{strat}:ip_ttl={ttl}")
                        for ttl in family["ttl_auto"]:
                            self._add(
                                items, seen, f"{label}_autottl{ttl}", f"{strat}:ip_autottl={ttl}"
                            )
            # BC2 23-seqovl padencap / tls_mod path via fake+multisplit
            if family.get("padencap") and scan_level != "single":
                for tmod in ("rnd,dupsid,padencap", "rnd,dupsid"):
                    strat = (
                        f"fake:blob=google:repeats=6:tls_mod={tmod}\n"
                        f"multisplit:pos=10,sniext+1:seqovl=1"
                    )
                    self._add(items, seen, f"std_seqovl_pad_{tmod[:12]}", strat)

        elif stype == "syndata":
            for blob in family["blobs"]:
                for tmod in family["tls_mods"]:
                    for plus in family["plus_split"]:
                        if blob:
                            strat = f"syndata:blob={blob}"
                            if tmod:
                                strat += f":tls_mod={tmod}"
                        else:
                            # Bare syndata (BC2 list_https_tls13)
                            strat = "syndata"
                        if plus:
                            strat = strat + "\nmultisplit:pos=1,midsld:seqovl=1"
                        label = f"std_syn_{blob or 'bare'}_{tmod[:15] or 'nomod'}" + (
                            "_split" if plus else ""
                        )
                        self._add(items, seen, label, strat)
                        if scan_level == "single":
                            return items
            if family.get("plus_hostfake") and scan_level != "single":
                strat = "syndata\nhostfakesplit:nofake2:tcp_ts=-1000"
                self._add(items, seen, "std_syn_bare_hf_ts", strat)

        elif stype == "tcpseg":
            for pos in family["positions"]:
                for r in family["repeats"]:
                    strat = f"tcpseg:pos={pos}:ip_id={family['ip_id']}:repeats={r}"
                    self._add(items, seen, f"std_tcpseg_p{pos}_r{r}", strat)
                    if scan_level == "single":
                        return items

        elif stype == "oob":
            in_range = family.get("in_range")
            for urp in family["urps"]:
                if in_range:
                    strat = f"--in-range={in_range}\noob:urp={urp}"
                else:
                    strat = f"oob:urp={urp}"
                self._add(items, seen, f"std_oob_urp{urp}", strat)
                if scan_level == "single":
                    return items

        elif stype == "multi_fake":
            repeat_pairs = family.get(
                "repeat_pairs",
                [(r, r) for r in family.get("repeats", [6])],
            )
            for b1, b2 in family["blob_pairs"]:
                for r1, r2 in repeat_pairs:
                    for fool in family["foolings"]:
                        f = f":{fool}" if fool else ""
                        strat = (
                            f"fake:blob={b1}:repeats={r1}{f}\n"
                            f"fake:blob={b2}:repeats={r2}{f}"
                        )
                        self._add(
                            items,
                            seen,
                            f"std_multi_{b1}+{b2}_r{r1}+{r2}_{fool or 'nofool'}",
                            strat,
                        )
                        if scan_level == "single":
                            return items

        elif stype == "triple_fake":
            for b1, b2, b3 in family["triples"]:
                for r in family["repeats"]:
                    for fool in family["foolings"]:
                        f = f":{fool}" if fool else ""
                        strat = (
                            f"fake:blob={b1}:repeats={r}{f}\n"
                            f"fake:blob={b2}:repeats={r}{f}\n"
                            f"fake:blob={b3}:repeats={r}{f}"
                        )
                        self._add(
                            items,
                            seen,
                            f"std_triple_{b1}+{b2}+{b3}_r{r}_{fool or 'nofool'}",
                            strat,
                        )
                        if scan_level == "single":
                            return items

        elif stype == "fake_multisplit":
            for fake_blob, pattern_blob in family["blob_pairs"]:
                if fake_blob == pattern_blob:
                    continue
                for pos in family["positions"]:
                    for seqovl in family["seqovl"]:
                        for r in family["repeats"]:
                            for fool in family["foolings"]:
                                f = f":{fool}" if fool else ""
                                fake_line = f"fake:blob={fake_blob}:repeats={r}{f}"
                                split_line = (
                                    f"multisplit:pos={pos}:seqovl={seqovl}"
                                    f":seqovl_pattern={pattern_blob}{f}"
                                )
                                strat = f"{fake_line}\n{split_line}"
                                label = (
                                    f"std_fms_{fake_blob}+{pattern_blob}_p{pos}_"
                                    f"s{seqovl}_r{r}_{fool or 'nofool'}"
                                )
                                self._add(items, seen, label, strat)
                                if scan_level == "single":
                                    return items

        elif stype == "multidisorder":
            for pos in family["positions"]:
                for fool in family["foolings"]:
                    f = f":{fool}" if fool else ""
                    for blob_name in family["seqovl_blobs"]:
                        strat = f"multidisorder:pos={pos}:seqovl_pattern={blob_name}{f}"
                        label = f"std_mdis_{pos}_{blob_name}_{fool or 'nofool'}"
                        self._add(items, seen, label, strat)
                        if scan_level == "single":
                            return items
                        for seqovl in family["seqovl"]:
                            strat = (
                                f"multidisorder:pos={pos}:seqovl={seqovl}"
                                f":seqovl_pattern={blob_name}{f}"
                            )
                            label = (
                                f"std_mdis_{pos}_s{seqovl}_{blob_name}_{fool or 'nofool'}"
                            )
                            self._add(items, seen, label, strat)
                            if scan_level == "single":
                                return items

        elif stype == "fake_multisplit_hostfake":
            for fake_blob, pattern_blob in family["blob_pairs"]:
                if fake_blob == pattern_blob:
                    continue
                for pos in family["positions"]:
                    for seqovl in family["seqovl"]:
                        for r in family["repeats"]:
                            for fool in family["foolings"]:
                                f = f":{fool}" if fool else ""
                                for host in family["hf_hosts"]:
                                    strat = (
                                        f"fake:blob={fake_blob}:repeats={r}{f}\n"
                                        f"multisplit:pos={pos}:seqovl={seqovl}"
                                        f":seqovl_pattern={pattern_blob}{f}\n"
                                        f"hostfakesplit:host={host}:nofake2{f}:repeats=1"
                                    )
                                    label = (
                                        f"std_fmsh_{fake_blob}+{pattern_blob}_p{pos}_"
                                        f"h{host.split('.')[0]}_r{r}_{fool or 'nofool'}"
                                    )
                                    self._add(items, seen, label, strat)
                                    if scan_level == "single":
                                        return items

        elif stype == "fake_multidisorder":
            for blob_name in family["blobs"]:
                for pos in family["positions"]:
                    for r in family["repeats"]:
                        for fool in family["foolings"]:
                            f = f":{fool}" if fool else ""
                            strat = (
                                f"fake:blob={blob_name}:repeats={r}{f}\n"
                                f"multidisorder:pos={pos}{f}"
                            )
                            label = (
                                f"std_fmd_{blob_name}_p{pos}_r{r}_{fool or 'nofool'}"
                            )
                            self._add(items, seen, label, strat)
                            if scan_level == "single":
                                return items

        elif stype == "fakedsplit":
            for pos in family["positions"]:
                for blob_name in family["pattern_blobs"]:
                    if blob_name == "0x00000000":
                        continue
                    for fool in family["foolings"]:
                        f = f":{fool}" if fool else ""
                        for r in family["repeats"]:
                            strat = f"fakedsplit:pos={pos}:pattern={blob_name}{f}:repeats={r}"
                            label = f"std_fds_p{pos}_{blob_name}_r{r}_{fool or 'nofool'}"
                            self._add(items, seen, label, strat)
                            if scan_level == "single":
                                return items
                            if family.get("ack_drop") and fool in ("", "tcp_ts=-1000") and r == 6:
                                self._add(items, seen, f"{label}_ackdrop", _with_ack_drop(strat))
                            if family.get("send_md5") and "tcp_md5" in (fool or "") and r == 6:
                                self._add(items, seen, f"{label}_sendmd5", _with_send_md5(strat))

        elif stype == "fakeddisorder":
            for pos in family["positions"]:
                for blob_name in family["pattern_blobs"]:
                    if blob_name == "0x00000000":
                        continue
                    for fool in family["foolings"]:
                        f = f":{fool}" if fool else ""
                        for r in family["repeats"]:
                            strat = f"fakeddisorder:pos={pos}:pattern={blob_name}{f}:repeats={r}"
                            label = f"std_fdd_p{pos}_{blob_name}_r{r}_{fool or 'nofool'}"
                            self._add(items, seen, label, strat)
                            if scan_level == "single":
                                return items
                            if family.get("ack_drop") and fool in ("", "tcp_ts=-1000") and r == 6:
                                self._add(items, seen, f"{label}_ackdrop", _with_ack_drop(strat))
                            if family.get("send_md5") and "tcp_md5" in (fool or "") and r == 6:
                                self._add(items, seen, f"{label}_sendmd5", _with_send_md5(strat))

        elif stype == "fake_fakedsplit":
            for blob_name in family["blobs"]:
                for pattern_blob in family["pattern_blobs"]:
                    for pos in family["positions"]:
                        for r in family["repeats"]:
                            for fool in family["foolings"]:
                                f = f":{fool}" if fool else ""
                                strat = (
                                    f"fake:blob={blob_name}:repeats={r}{f}\n"
                                    f"fakedsplit:pos={pos}:pattern={pattern_blob}{f}"
                                )
                                label = (
                                    f"std_ffds_{blob_name}+{pattern_blob}_p{pos}_"
                                    f"r{r}_{fool or 'nofool'}"
                                )
                                self._add(items, seen, label, strat)
                                if scan_level == "single":
                                    return items

        elif stype == "tcp_ipfrag":
            for pos in family["positions"]:
                strat = f"send:ipfrag:ipfrag_pos_tcp={pos}\ndrop"
                label = f"std_tcp_ipfrag_pos{pos}"
                self._add(items, seen, label, strat)
                if scan_level == "single":
                    return items
            for pos in family["positions"]:
                for blob_name in family.get("combo_blobs", [""]):
                    if not blob_name:
                        continue
                    for r in family["repeats"]:
                        strat = (
                            f"fake:blob={blob_name}:repeats={r}\n"
                            f"send:ipfrag:ipfrag_pos_tcp={pos}\n"
                            f"drop"
                        )
                        label = f"std_tcp_fake_ipfrag_{blob_name}_r{r}_pos{pos}"
                        self._add(items, seen, label, strat)
                        if scan_level == "single":
                            return items

        elif stype == "udp_discord":
            blobs = family.get("blobs", ["discord_udp"])
            for blob_name in blobs:
                for r in family["repeats"]:
                    strat = f"fake:blob={blob_name}:repeats={r}"
                    self._add(items, seen, f"std_udp_{blob_name}_r{r}", strat)
                    if scan_level == "single":
                        return items
                    for ttl in family.get("ttl_static", []):
                        self._add(
                            items,
                            seen,
                            f"std_udp_{blob_name}_r{r}_ttl{ttl}",
                            f"{strat}:ip_ttl={ttl}",
                        )
                    for ttl in family.get("ttl_auto", []):
                        self._add(
                            items,
                            seen,
                            f"std_udp_{blob_name}_r{r}_autottl",
                            f"{strat}:ip_autottl={ttl}",
                        )

        elif stype == "udp_quic":
            for ports in family["port_ranges"]:
                for blob_name in family["blobs"]:
                    for r in family["repeats"]:
                        s = (
                            f"--filter-udp={ports} "
                            f"--blob=QUIC:@{_blob_abs(blob_name)} "
                            f"--payload=quic_initial "
                            f"--lua-desync=fake:blob=QUIC:repeats={r}"
                        )
                        self._add(items, seen, f"std_udp_quic_{blob_name}_r{r}", s, protocol="quic")
                        if scan_level == "single":
                            return items

        elif stype == "udp_game":
            for ports in family["port_ranges"]:
                for blob_name in family["blobs"]:
                    for r in family["repeats"]:
                        for orng in family["out_range"]:
                            s = (
                                f"--filter-udp={ports} "
                                f"--blob=GAME:@{_blob_abs(blob_name)} "
                                f"--payload=unknown "
                                f"--lua-desync=fake:blob=GAME:repeats={r}"
                                + (f" --out-range={orng}" if orng else "")
                            )
                            self._add(items, seen, f"std_udp_game_r{r}_{orng or 'no'}", s)
                            if scan_level == "single":
                                return items

        elif stype == "udp_multiblob":
            for b1, b2 in family["profiles"]:
                for r in family["repeats"]:
                    s = (
                        f"--filter-udp=443 --filter-l7=stun "
                        f"--blob=STUN:@{_blob_abs(b1)} "
                        f"--payload=stun "
                        f"--lua-desync=fake:blob=STUN:repeats={r}\n"
                        f"--filter-udp=443 --filter-l7=discord "
                        f"--blob=DISC:@{_blob_abs(b2)} "
                        f"--payload=discord_ip_discovery "
                        f"--lua-desync=fake:blob=DISC:repeats={r}"
                    )
                    self._add(items, seen, f"std_udp_multiblob_{b1}+{b2}_r{r}", s)
                    if scan_level == "single":
                        return items

        elif stype == "fake_hostfake":
            for blob_name in family["blobs"]:
                for r in family["repeats"]:
                    for fool in family["foolings"]:
                        f = f":{fool}" if fool else ""
                        for hf in family["hf_variants"]:
                            if hf == "base":
                                hf_core = f"hostfakesplit:nofake2{f}:repeats=1"
                            else:
                                # hf is disorder_after (or other valid token)
                                hf_core = f"hostfakesplit:{hf}:nofake2{f}:repeats=1"
                            strat = f"fake:blob={blob_name}:repeats={r}{f}\n{hf_core}"
                            self._add(
                                items,
                                seen,
                                f"std_fh_{blob_name}_r{r}_{hf}_{fool or 'nofool'}",
                                strat,
                            )
                            if scan_level == "single":
                                return items

        elif stype == "http_simple":
            for variant in family["variants"]:
                label = f"std_http_{variant.replace(':', '_')}"
                self._add(items, seen, label, variant, protocol="http")
                if scan_level == "single":
                    return items

        elif stype == "http_fake":
            for blob_name in family["blobs"]:
                blob = f":blob={blob_name}"
                for repeats in family["repeats"]:
                    for fool in family["foolings"]:
                        fool_str = f":{fool}" if fool else ""
                        strat = f"fake{blob}:repeats={repeats}{fool_str}"
                        label = f"std_http_fake_{blob_name}_r{repeats}_{fool or 'nofool'}"
                        self._add(items, seen, label, strat, protocol="http")
                        if scan_level == "single":
                            return items

        elif stype == "http_tls_dual":
            for blob_name in family["http_blobs"]:
                for repeats in family["repeats"]:
                    for fool in family["foolings"]:
                        fool_str = f":{fool}" if fool else ""
                        strat = f"fake:blob={blob_name}:repeats={repeats}{fool_str}"
                        label = f"std_http_tls_dual_{blob_name}_r{repeats}_{fool or 'nofool'}"
                        self._add(items, seen, label, strat, protocol="http")
                        if scan_level == "single":
                            return items

        elif stype == "quic_fake":
            for blob_name in family["blobs"]:
                for r in family["repeats"]:
                    for fool in family.get("foolings", [""]):
                        fool_str = f":{fool}" if fool else ""
                        strat = f"fake:blob={blob_name}:repeats={r}{fool_str}"
                        label = f"std_quic_fake_{blob_name}_r{r}_{fool or 'nofool'}"
                        self._add(items, seen, label, strat, protocol="quic")
                        if scan_level == "single":
                            return items
            if family.get("ip6_send_drop"):
                for fool in family.get("ip6_fools", FAST_FOOLINGS_IPV6):
                    self._add(
                        items,
                        seen,
                        f"std_quic_ip6_{fool.replace(':', '_')}",
                        _with_ip6_send_drop(fool),
                        protocol="quic",
                    )

        elif stype == "quic_gv":
            for blob_name in family["blobs"]:
                for r in family["repeats"]:
                    strat = f"fake:blob={blob_name}:repeats={r}"
                    label = f"std_quic_gv_{blob_name}_r{r}"
                    self._add(items, seen, label, strat, protocol="quic")
                    if scan_level == "single":
                        return items

        elif stype == "quic_ipfrag":
            for pos in family["positions"]:
                strat = f"send:ipfrag:ipfrag_pos_udp={pos}\ndrop"
                label = f"std_quic_ipfrag_pos{pos}"
                self._add(items, seen, label, strat, protocol="quic")
                if scan_level == "single":
                    return items
            for pos in family["positions"]:
                for r in family["repeats"]:
                    strat = (
                        f"fake:blob=fake_default_quic:repeats={r}\n"
                        f"send:ipfrag:ipfrag_pos_udp={pos}\n"
                        f"drop"
                    )
                    label = f"std_quic_fake_ipfrag_r{r}_pos{pos}"
                    self._add(items, seen, label, strat, protocol="quic")
                    if scan_level == "single":
                        return items

        return items

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

