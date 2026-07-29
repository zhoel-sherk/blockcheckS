"""Strategy matrix generator — combinatorial strategy generation.

Sources:
  1. custom — blockcheck2.d/custom/list_*.txt (flat strategy lists)
  2. standard — hardcoded replicas of blockcheck2.d/standard/*.sh generators
  3. configs — pre-built .conf files from blockcheckS/configs/
  4. user-matrix — user-provided strategy list file (--user-matrix flag)

SCANLEVEL (from blockcheck2.sh):
  single — 1st strategy of each type only
  fast   — stop at first PASS per type group (default)
  full   — all combinations

Extensibility:
  register_generator(name, gen) — plug in custom StrategyGenerator subclasses
"""

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from blockchecks.engine.db_logger import StateDB


@dataclass
class StrategyItem:
    label: str
    strategy: str
    is_config: bool = False


@dataclass
class StrategyPair:
    tcp: StrategyItem
    udp: StrategyItem


# ── Base class ──

class StrategyGenerator(ABC):
    @abstractmethod
    async def generate(self, protocol: str = "tls12",
                        state_db: StateDB = None,
                        domain: str = "",
                        scan_level: str = "fast",
                        max_count: int = 100,
                        run_set: set = None) -> list[StrategyItem]:
        ...


# ── Custom list generator (blockcheck2.d/custom/) ──

class CustomListGenerator(StrategyGenerator):
    """Load strategies from blockcheck2.d/custom/list_*.txt files."""

    FILE_MAP = {
        "http": "list_http.txt",
        "tls12": "list_https_tls12.txt",
        "tls13": "list_https_tls13.txt",
        "quic": "list_quic.txt",
        "udp_voice": "list_udp_voice.txt",
    }

    def __init__(self, base_dir: str = "/opt/zapret2/blockcheck2.d/custom"):
        self.base_dir = base_dir

    async def generate(self, protocol: str = "tls12",
                        state_db: StateDB = None,
                        domain: str = "",
                        scan_level: str = "fast",
                        max_count: int = 100,
                        run_set: set = None) -> list[StrategyItem]:
        filename = self.FILE_MAP.get(protocol)
        if not filename:
            return []

        path = os.path.join(self.base_dir, filename)
        if not os.path.exists(path):
            return []

        items = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                label = line[:60].replace(" ", "_").replace(":", "_")
                items.append(StrategyItem(label=label, strategy=line))
                if scan_level == "single" and items:
                    break
        return items[:max_count]


# ── Config file generator (blockcheckS/configs/ .conf files) ──

class ConfigFileGenerator(StrategyGenerator):
    """Load pre-built .conf files."""

    def __init__(self, config_dir: str = None):
        from blockchecks.engine.config import CONFIGS_DIR
        self.config_dir = config_dir or CONFIGS_DIR

    async def generate(self, protocol: str = "tls12",
                        state_db: StateDB = None,
                        domain: str = "",
                        scan_level: str = "fast",
                        max_count: int = 100,
                        run_set: set = None) -> list[StrategyItem]:
        if not os.path.isdir(self.config_dir):
            return []

        items = []
        filter_term = "udp_voice" if protocol == "udp_voice" else None
        for fname in sorted(os.listdir(self.config_dir)):
            if not fname.endswith(".conf"):
                continue
            if filter_term and filter_term not in fname:
                continue
            if not filter_term and "udp_voice" in fname:
                continue
            path = os.path.join(self.config_dir, fname)
            label = fname.replace(".conf", "")
            items.append(StrategyItem(label=label, strategy=path,
                                      is_config=True))
            if scan_level == "single" and items:
                break
        return items[:max_count]


# ── Standard generators (hardcoded from blockcheck2.d/standard/*.sh) ──

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

    async def generate(self, protocol: str = "tls12",
                        state_db: StateDB = None,
                        domain: str = "",
                        scan_level: str = "fast",
                        max_count: int = 100,
                        run_set: set = None) -> list[StrategyItem]:
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

    async def generate(self, protocol: str = "tls12",
                        state_db: StateDB = None,
                        domain: str = "",
                        scan_level: str = "fast",
                        max_count: int = 100,
                        run_set: set = None) -> list[StrategyItem]:
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
    """fakedsplit (faked) + position + fooling."""

    async def generate(self, protocol: str = "tls12",
                        state_db: StateDB = None,
                        domain: str = "",
                        scan_level: str = "fast",
                        max_count: int = 100,
                        run_set: set = None) -> list[StrategyItem]:
        items = []
        for pos in [1, "midsld", "sniext+1"]:
            for fool in ["", "tcp_md5", "tcp_ts=-1000"]:
                fool_part = _fooling_clause(fool)
                strat = f"multisplit:pos={pos}:seqovl=1{fool_part}"
                label = f"faked_p{pos}_{fool or 'nofool'}"
                items.append(StrategyItem(label=label, strategy=strat))
                if scan_level == "single":
                    return items[:max_count]
                if len(items) >= max_count:
                    return items[:max_count]
        return items[:max_count]


class FakeMultiGenerator(StrategyGenerator):
    """Multi-blob fake (2-3 blobs simultaneously)."""

    async def generate(self, protocol: str = "tls12",
                        state_db: StateDB = None,
                        domain: str = "",
                        scan_level: str = "fast",
                        max_count: int = 100,
                        run_set: set = None) -> list[StrategyItem]:
        items = []
        blob_pairs = [("stun", "max_ru"), ("stun", "google"),
                       ("max_ru", "google")]
        for r in [6, 3]:
            for fool in ["tcp_ts=-1000", ""]:
                fool_part = _fooling_clause(fool)
                for b1, b2 in blob_pairs:
                    strat = (f"fake:blob={b1}:repeats={r}{fool_part}\n"
                             f"fake:blob={b2}:repeats={r}{fool_part}")
                    label = f"fake_multi_{b1}+{b2}_r{r}_{fool or 'nofool'}"
                    items.append(StrategyItem(label=label, strategy=strat))
                    if scan_level == "single":
                        return items[:max_count]
                    if len(items) >= max_count:
                        return items[:max_count]
        return items[:max_count]


class FakeSplitComboGenerator(StrategyGenerator):
    """fake + fakedsplit combined."""

    async def generate(self, protocol: str = "tls12",
                        state_db: StateDB = None,
                        domain: str = "",
                        scan_level: str = "fast",
                        max_count: int = 100,
                        run_set: set = None) -> list[StrategyItem]:
        items = []
        for r in [6, 3]:
            for fool in ["", "tcp_ts=-1000"]:
                fool_part = _fooling_clause(fool)
                for blob in ["", "stun"]:
                    blob_part = f":blob={blob}" if blob else ""
                    strat = (f"fake{blob_part}:repeats={r}{fool_part}\n"
                             f"multisplit:pos=1,midsld:seqovl=1{fool_part}")
                    label = f"fake+faked_{blob or 'none'}_r{r}_{fool or 'nofool'}"
                    items.append(StrategyItem(label=label, strategy=strat))
                    if len(items) >= max_count:
                        return items[:max_count]
        return items[:max_count]


# ── User matrix (--user-matrix flag) ──

class UserMatrixGenerator(StrategyGenerator):
    """Load strategies from user-provided file (one per line)."""

    def __init__(self, filepath: str):
        self.filepath = filepath

    async def generate(self, protocol: str = "tls12",
                        state_db: StateDB = None,
                        domain: str = "",
                        scan_level: str = "fast",
                        max_count: int = 100,
                        run_set: set = None) -> list[StrategyItem]:
        if not os.path.exists(self.filepath):
            print(f"[matrix] User matrix file not found: {self.filepath}")
            return []

        items = []
        with open(self.filepath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Filter by protocol: skip UDP-only strategies for TCP generation
                if protocol != "udp_voice" and not any(kw in line.lower() for kw in ("--filter-udp", "--qnum=201")):
                    is_udp_only = any(kw in line for kw in ("filter-udp", "blob=discord_udp", "discord_ip_discovery"))
                    if is_udp_only:
                        continue
                if protocol == "udp_voice" and "tcp" in line.lower() and "udp" not in line.lower():
                    continue
                label = line[:50].replace(" ", "_").replace(":", "_")
                items.append(StrategyItem(label=label, strategy=line))
                if scan_level == "single" and items:
                    break
        return items[:max_count]


# ── Orchestrator ──

# ── Flowseal strategy generator (35+ combos from Flowseal ALT2 patterns) ──

class FlowsealGenerator(StrategyGenerator):
    """Flowseal ALT2 → nfqws2 strategy generator.

    Generates 35+ combos based on Flowseal's battle-tested parameters:
    - multi-blob fake (2-3 blobs simultaneously)
    - multisplit with seqovl variations
    - hostfakesplit with host substitution
    - fake+tls_mod SNI spoofing
    - fooling variations (ts, md5, badseq)
    """

    async def generate(self, protocol: str = "tls12",
                        state_db: StateDB = None,
                        domain: str = "",
                        scan_level: str = "fast",
                        max_count: int = 100,
                        run_set: set = None) -> list[StrategyItem]:
        items = []
        known_working = list(run_set or [])
        if state_db and domain and not known_working:
            known_working = await state_db.get_working_tcp(domain)

        # ── 1. Multi-blob fake (most effective on Fryazino) ──
        blob_pairs = [("stun", "max_ru"), ("stun", "google"),
                       ("max_ru", "google"), ("stun", "4pda")]
        for b1, b2 in blob_pairs:
            for r in [6, 3, 8]:
                for fool in ["tcp_ts=-1000", "tcp_md5"]:
                    strat = (f"fake:blob={b1}:repeats={r}:{fool}\n"
                             f"fake:blob={b2}:repeats={r}:{fool}")
                    label = f"flw_multi_{b1}+{b2}_r{r}_{fool}"
                    items.append(StrategyItem(label=label, strategy=strat))
                    if scan_level == "single":
                        return items[:max_count]

        # ── 2. Multisplit with seqovl (Flowseal ALT2 pattern) ──
        for pos in [1, 2, "midsld", "sniext+1"]:
            for seqovl in [568, 652, 664, 681]:
                for blob_name in ["google", "max_ru", "4pda"]:
                    strat = f"multisplit:pos={pos}:seqovl={seqovl}:seqovl_pattern={blob_name}"
                    label = f"flw_split_p{pos}_s{seqovl}_{blob_name}"
                    items.append(StrategyItem(label=label, strategy=strat))
                    if len(items) >= max_count:
                        return items[:max_count]

        # ── 3. Fake + TLS mod (SNI spoofing) ──
        for blob in ["google", "max_ru"]:
            for sni in ["www.google.com", "fonts.google.com", "ya.ru"]:
                for r in [6, 8]:
                    strat = (f"fake:blob={blob}:repeats={r}:tcp_ts=-1000"
                             f":tls_mod=rnd,dupsid,sni={sni}")
                    label = f"flw_fake_tlsmod_{blob}_sni={sni}_r{r}"
                    items.append(StrategyItem(label=label, strategy=strat))

        # ── 4. Hostfakesplit with host substitution ──
        for host in ["www.google.com", "ozon.ru"]:
            for fool in ["tcp_md5", "tcp_ts=-1000"]:
                strat = f"hostfakesplit:host={host}:{fool}:repeats=1"
                label = f"flw_hf_host={host}_{fool}"
                items.append(StrategyItem(label=label, strategy=strat))
                # With disorder_after
                strat2 = f"hostfakesplit:disorder_after:host={host}:{fool}:repeats=1"
                label2 = f"flw_hf_disorder_host={host}_{fool}"
                items.append(StrategyItem(label=label2, strategy=strat2))

        # ── 5. Fake with null blob + repeats (Flowseal game filter style) ──
        for r in [6, 12]:
            for fool in ["tcp_ts=-1000", "tcp_md5"]:
                strat = f"fake:blob=0x00000000:repeats={r}:{fool}"
                label = f"flw_null_r{r}_{fool}"
                items.append(StrategyItem(label=label, strategy=strat))

        # ── 6. Blind fake (no blob, auto-generated) — rarely works, but Flowseal has it ──
        for r in [6, 11]:
            strat = f"fake:repeats={r}:tcp_ts=-1000"
            label = f"flw_blind_r{r}"
            items.append(StrategyItem(label=label, strategy=strat))

        # ── 7. ip-id=zero for Google (Flowseal-specific) ──
        for r in [6, 8]:
            strat = f"fake:blob=google:repeats={r}:tcp_ts=-1000:ip_id=zero"
            label = f"flw_google_ipid_r{r}"
            items.append(StrategyItem(label=label, strategy=strat))

        return items[:max_count]

# ── Extended parameters (from blockcheck.sh def.inc + standard scripts) ──

# Full foolings matching blockcheck2.sh standard tests
ALL_FOOLINGS_TCP = [
    "tcp_ts=-1000",           # most effective on Fryazino
    "",
    "tcp_md5",
    "tcp_ack=-66000:tcp_ts_up",
    "tcp_seq=-3000",
    "tcp_seq=1000000",
    "tcp_flags_unset=ACK",
    "tcp_flags_set=SYN",
]
ALL_FOOLINGS_UDP = ["badsum"]
ALL_FOOLINGS_IPV6 = ["ip6_hopbyhop"]  # минимально, остальные 4 — низкий приоритет

# Extended repeats, TTL
ALL_REPEATS = [6, 3, 1, 8, 10, 11, 12, 2, 5, 7, 9, 15, 20]  # 100,260 only for tcpseg
ALL_TTL = [1, 5, 7, 12, 63, 64, 127, 128, 255]  # 63=ttl_minus_1, boundary values for other ISPs
ALL_AUTOTTL = ["-1,3-20", "-2,5-15", "-3,7-12", "-4,3-20", "-5,5-15"]

# All split positions from blockcheck2.sh
ALL_SPLIT_POSITIONS = [
    "1", "2", "3", "23", "45", "midsld", "sniext+1", "sniext+4", "host+1",
    "1,midsld", "1,midsld,1220",
    "1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1",
]
# Sequence overlap values (Flowseal variants)
ALL_SEQOVL = [1, 568, 652, 664, 679, 681]

# TLS modification flags (from blockcheck2.sh standard scripts)
TLS_MODS = [
    "",                          # no mod
    "rnd",                       # randomize extensions
    "rnd,dupsid",                # + duplicate session ID
    "rnd,dupsid,padencap",        # + pad encapsulation
    "rnd,dupsid,sni=www.google.com",  # + SNI substitution
    "rnd,dupsid,sni=fonts.google.com",
    "rnd,dupsid,sni=ya.ru",
]

# All TCP blobs (extended from Flowseal)
ALL_BLOBS_TCP = ["stun", "max_ru", "google", "4pda", "tls_clienthello"]

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
            "repeats": [r for r in ALL_REPEATS if r not in (100, 260)],  # skip tcpseg-only values
            "foolings": ALL_FOOLINGS_TCP,
            "ttl_static": ALL_TTL,
            "ttl_auto": ALL_AUTOTTL,
            "tls_mods": TLS_MODS[:3],  # rnd, rnd+dupsid, rnd+dupsid+padencap
        },
        # 35-hostfake.sh: hostfakesplit variants
        "hostfake": {
            "foolings": ALL_FOOLINGS_TCP[:5],  # skip tcp_flags
            "variants": ["base", "disorder", "nofake1", "midhost=midsld", "nodrop"],
            "ttl_static": ALL_TTL,
            "ttl_auto": ALL_AUTOTTL,
        },
        # 30-faked.sh + 20-multi.sh: multisplit/fakedsplit positions
        "multisplit": {
            "repeats": [1, 6, 11],
            "positions": ALL_SPLIT_POSITIONS,
            "foolings": ALL_FOOLINGS_TCP[:4],  # no tcp_seq/tcp_flags for split
            "seqovl": ALL_SEQOVL,
            "seqovl_blobs": ALL_BLOBS_TCP,
            "ttl_static": ALL_TTL,
            "ttl_auto": ALL_AUTOTTL,
        },
        # 24-syndata.sh: syndata + blob + TLS mod
        "syndata": {
            "blobs": ["0x1603", "fake_default_tls"],
            "tls_mods": ["rnd,dupsid", "rnd,dupsid,sni=www.google.com"],
            "plus_split": [False, True],  # syndata alone, or syndata+split
        },
        # 15-misc.sh: tcpseg (TCP segmentation)
        "tcpseg": {
            "positions": ["0,1", "0,midsld"],
            "repeats": [1, 20, 100, 260],
            "ip_id": "rnd",
        },
        # 17-oob.sh: out-of-band urgent pointer
        "oob": {
            "urps": ["b", "0", "2", "midsld"],
            "in_range": "-s1",
        },
        # Multi-blob fake with pairs (blockcheckS extension)
        "multi_fake": {
            "blob_pairs": [("stun","max_ru"),("stun","google"),
                           ("max_ru","google"),("stun","4pda")],
            "repeats": [6, 3, 8, 12, 11, 2],
            "foolings": ["tcp_ts=-1000", "tcp_md5"],
        },
        # Fake + hostfakesplit combo (60-fake-hostfake.sh)
        "fake_hostfake": {
            "blobs": ALL_BLOBS_TCP,
            "repeats": [6, 3, 8, 11, 2],
            "foolings": ["tcp_ts=-1000", "tcp_md5"],
            "hf_variants": ["base", "disorder"],
        },
        # ── Flowseal UDP families (full nfqws2 inline configs) ──
        "udp_discord": {
            "port_ranges": ["19294-19344,50000-50100"],
            "blobs": ["quic_initial_dbankcloud_ru", "discord_udp"],
            "repeats": [6, 12, 3, 2],
            "out_range": [None, "n1-<n3", "n1-<n4"],
            "dual_blob": [False, True],  # ALT12 dual-blob pattern
        },
        "udp_quic": {
            "port_ranges": ["443"],
            "blobs": ["quic_initial_www_google_com", "quic_initial_dbankcloud_ru"],
            "repeats": [1, 2, 5, 6, 10, 11, 20],  # blockcheck.sh 90-quic.sh spectrum
        },
        "udp_game": {
            "port_ranges": ["1024-65535"],
            "blobs": ["quic_initial_dbankcloud_ru"],
            "repeats": [10, 12, 14],
            "out_range": [None, "n1-<n3", "n1-<n4", "n1-<n5"],
        },
    }

    def __init__(self, strategy_types: list[str] | None = None):
        self.strategy_types = strategy_types or list(self.STRATEGY_FAMILIES.keys())
        # Validate
        for t in self.strategy_types:
            if t not in self.STRATEGY_FAMILIES and t != "all":
                raise ValueError(f"Unknown strategy type: {t}")

    async def generate(self, protocol: str = "tls12",
                        state_db: StateDB = None,
                        domain: str = "",
                        scan_level: str = "fast",
                        max_count: int = 500,
                        run_set: set = None) -> list[StrategyItem]:
        """Generate strategies from specified families."""
        items = []
        seen: set[str] = set()  # dedup
        known_working = list(run_set or [])
        if state_db and domain and not known_working:
            known_working = await state_db.get_working_tcp(domain)

        types = self.strategy_types
        if "all" in types:
            types = list(self.STRATEGY_FAMILIES.keys())

        for stype in types:
            family = self.STRATEGY_FAMILIES.get(stype)
            if not family:
                continue
            new = self._expand_family(stype, family, scan_level, seen, known_working)
            items.extend(new)
            if len(items) >= max_count:
                break

        return items[:max_count]

    def _expand_family(self, stype: str, family: dict,
                        scan_level: str, seen: set, known_working: list
                        ) -> list[StrategyItem]:
        """Expand one strategy family into items."""
        items = []
        first_item_added = False

        if stype == "fake":
            for blob_name in family["blobs"]:
                blob = f":blob={blob_name}"
                for repeats in family["repeats"]:
                    for fool in family["foolings"]:
                        fool_str = f":{fool}" if fool else ""
                        # Base (no TTL)
                        strat = f"fake{blob}:repeats={repeats}{fool_str}"
                        label = f"std_fake_{blob_name}_r{repeats}_{fool or 'nofool'}"
                        self._add(items, seen, label, strat)
                        first_item_added = True

                        if scan_level == "single":
                            return items

                        # Skip TTL if base known-working
                        if scan_level == "fast" and label in known_working:
                            continue

                        # TTL variants
                        for ttl in family["ttl_static"]:
                            self._add(items, seen,
                                      f"{label}_ttl{ttl}",
                                      f"{strat}:ip_ttl={ttl}")
                        for ttl in family["ttl_auto"]:
                            self._add(items, seen,
                                      f"{label}_autottl{ttl}",
                                      f"{strat}:ip_autottl={ttl}")
                        # TLS mods (only for google blob — most common target)
                        if blob_name == "google" and not fool:
                            for tmod in family["tls_mods"]:
                                if not tmod:
                                    continue
                                for r in [6, 8]:
                                    s = f"fake:blob={blob_name}:repeats={r}:tls_mod={tmod}"
                                    self._add(items, seen,
                                              f"std_fake_google_r{r}_tlsmod={tmod[:20]}",
                                              s)

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

                    if scan_level == "fast" and label in known_working:
                        continue
                    if scan_level == "single":
                        return items

                    for ttl in family["ttl_static"]:
                        self._add(items, seen, f"{label}_ttl{ttl}", f"{core}:ip_ttl={ttl}")
                    for ttl in family["ttl_auto"]:
                        self._add(items, seen, f"{label}_autottl{ttl}", f"{core}:ip_autottl={ttl}")

        elif stype == "multisplit":
            # Limit: most useful pos,seqovl pairs
            repeats_list = family.get("repeats", [1])
            pos_seqovl_pairs = [
                ("1", 1), ("2", 652), ("midsld", 1),
                ("sniext+1", 679), ("1,midsld", 1),
                ("host+1", 681),
            ]
            for pos, seqovl in pos_seqovl_pairs:
                for fool in family["foolings"]:
                    fool_str = f":{fool}" if fool else ""
                    for blob_name in family["seqovl_blobs"]:
                        strat = (f"multisplit:pos={pos}:seqovl={seqovl}"
                                 f":seqovl_pattern={blob_name}{fool_str}")
                        label = f"std_split_{pos}_s{seqovl}_{blob_name}_{fool or 'nofool'}"
                        self._add(items, seen, label, strat)
                        if scan_level == "single":
                            return items
                        for ttl in family["ttl_static"]:
                            self._add(items, seen, f"{label}_ttl{ttl}", f"{strat}:ip_ttl={ttl}")
                        for ttl in family["ttl_auto"]:
                            self._add(items, seen, f"{label}_autottl{ttl}", f"{strat}:ip_autottl={ttl}")

        elif stype == "syndata":
            for blob in family["blobs"]:
                for tmod in family["tls_mods"]:
                    for plus in family["plus_split"]:
                        strat = f"syndata:blob={blob}"
                        if tmod:
                            strat += f":tls_mod={tmod}"
                        if plus:
                            strat = f"syndata:blob={blob}\nmultisplit:pos=1,midsld:seqovl=1"
                        label = f"std_syn_{blob}_{tmod[:15] or 'nomod'}" + ("_split" if plus else "")
                        self._add(items, seen, label, strat)

        elif stype == "tcpseg":
            for pos in family["positions"]:
                for r in family["repeats"]:
                    strat = f"tcpseg:pos={pos}:ip_id={family['ip_id']}:repeats={r}"
                    self._add(items, seen, f"std_tcpseg_p{pos}_r{r}", strat)

        elif stype == "oob":
            for urp in family["urps"]:
                strat = f"oob:urp={urp}"
                self._add(items, seen, f"std_oob_urp{urp}", strat)

        elif stype == "multi_fake":
            for (b1, b2) in family["blob_pairs"]:
                for r in family["repeats"]:
                    for fool in family["foolings"]:
                        f = f":{fool}" if fool else ""
                        strat = (f"fake:blob={b1}:repeats={r}{f}\n"
                                 f"fake:blob={b2}:repeats={r}{f}")
                        self._add(items, seen, f"std_multi_{b1}+{b2}_r{r}_{fool or 'nofool'}", strat)

        elif stype == "udp_discord":
            for ports in family["port_ranges"]:
                for blob_name in family["blobs"]:
                    for r in family["repeats"]:
                        for dual in family["dual_blob"]:
                            if dual:
                                # ALT12 dual-blob pattern: stun + dbankcloud
                                clue = f"--filter-udp={ports} --filter-l7=discord,stun "
                                clue += f"--blob=STUN:@/opt/zapret2/blobs/stun.bin "
                                clue += f"--blob=DKCLOUD:@/opt/zapret2/blobs/quic_initial_dbankcloud_ru.bin "
                                clue += f"--payload=discord_ip_discovery,stun "
                                clue += f"--lua-desync=fake:blob=STUN:repeats={r//2} "
                                clue += f"--lua-desync=fake:blob=DKCLOUD:repeats={r//2}"
                                for orng in family["out_range"]:
                                    s = clue + (f" --out-range={orng}" if orng else "")
                                    self._add(items, seen, f"std_udp_discord_dual_r{r}_{orng or 'no'}", s)
                            else:
                                clue = f"--filter-udp={ports} --filter-l7=discord,stun "
                                clue += f"--blob=DISCORD:@/opt/zapret2/blobs/{blob_name}.bin "
                                clue += f"--payload=discord_ip_discovery,stun "
                                clue += f"--lua-desync=fake:blob=DISCORD:repeats={r}"
                                for orng in family["out_range"]:
                                    s = clue + (f" --out-range={orng}" if orng else "")
                                    self._add(items, seen, f"std_udp_d_{blob_name}_r{r}_{orng or 'no'}", s)

        elif stype == "udp_quic":
            for ports in family["port_ranges"]:
                for blob_name in family["blobs"]:
                    for r in family["repeats"]:
                        s = (f"--filter-udp={ports} "
                             f"--blob=QUIC:@/opt/zapret2/blobs/{blob_name}.bin "
                             f"--payload=quic_initial "
                             f"--lua-desync=fake:blob=QUIC:repeats={r}")
                        self._add(items, seen, f"std_udp_quic_{blob_name}_r{r}", s)

        elif stype == "udp_game":
            for ports in family["port_ranges"]:
                for blob_name in family["blobs"]:
                    for r in family["repeats"]:
                        for orng in family["out_range"]:
                            s = (f"--filter-udp={ports} "
                                 f"--blob=GAME:@/opt/zapret2/blobs/{blob_name}.bin "
                                 f"--payload=unknown "
                                 f"--lua-desync=fake:blob=GAME:repeats={r}" +
                                 (f" --out-range={orng}" if orng else ""))
                            self._add(items, seen, f"std_udp_game_r{r}_{orng or 'no'}", s)

        elif stype == "fake_hostfake":
            for blob_name in family["blobs"]:
                for r in family["repeats"]:
                    for fool in family["foolings"]:
                        f = f":{fool}" if fool else ""
                        for hf in family["hf_variants"]:
                            hf_core = (f"hostfakesplit:{hf}:nofake2{f}:repeats=1"
                                       if hf != "base" else
                                       f"hostfakesplit:nofake2{f}:repeats=1")
                            strat = f"fake:blob={blob_name}:repeats={r}{f}\n{hf_core}"
                            self._add(items, seen,
                                      f"std_fh_{blob_name}_r{r}_{hf}_{fool or 'nofool'}", strat)

        return items

    @staticmethod
    def _add(items: list, seen: set, label: str, strategy: str) -> None:
        """Dedup by strategy string."""
        key = strategy.strip()
        if key not in seen:
            seen.add(key)
            items.append(StrategyItem(label=label, strategy=strategy))

class MatrixGenerator:
    """Orchestrates multiple strategy sources with SCANLEVEL + state.db."""

    REGISTRY = {
        "custom": CustomListGenerator,
        "flowseal": FlowsealGenerator,
        "standard": StandardGenerator,
        "configs": ConfigFileGenerator,
        "fake": FakeTcpGenerator,
        "faked": FakedTcpGenerator,
        "hostfake": HostfakeTcpGenerator,
        "fake_multi": FakeMultiGenerator,
        "fake_faked": FakeSplitComboGenerator,
    }

    def __init__(self):
        self._generators: dict[str, StrategyGenerator] = {}

    def register(self, name: str, gen: StrategyGenerator):
        self._generators[name] = gen

    def _ensure_registered(self, name: str):
        if name not in self._generators and name in self.REGISTRY:
            self._generators[name] = self.REGISTRY[name]()

    async def generate_tcp(self,
                            sources: list[str] = None,
                            domain: str = "discord.com",
                            scan_level: str = "fast",
                            max_count: int = 100,
                            state_db: StateDB = None,
                            protocol: str = "tls12",
                            user_matrix: str = "",
                            run_set: set = None,
                            ) -> list[StrategyItem]:
        """Generate TCP strategies from specified sources."""
        if not sources:
            sources = ["custom", "configs"]

        if user_matrix:
            self.register("user", UserMatrixGenerator(user_matrix))
            sources = ["user"]

        all_items = []
        for src_name in sources:
            self._ensure_registered(src_name)
            gen = self._generators.get(src_name)
            if not gen:
                continue
            items = await gen.generate(
                protocol=protocol, state_db=state_db,
                domain=domain, scan_level=scan_level,
                max_count=max_count // len(sources) or max_count,
                run_set=run_set,
            )
            all_items.extend(items)

        # Dedup by strategy string while preserving order
        seen: set[str] = set()
        deduped: list[StrategyItem] = []
        for item in all_items:
            if item.strategy in seen:
                continue
            seen.add(item.strategy)
            deduped.append(item)
        return deduped[:max_count]

    async def generate_udp(self,
                            sources: list[str] = None,
                            domain: str = "discord.com",
                            scan_level: str = "fast",
                            max_count: int = 50,
                            state_db: StateDB = None,
                            user_matrix: str = "",
                            ) -> list[StrategyItem]:
        """Generate UDP strategies."""
        if not sources:
            sources = ["custom"]

        if user_matrix:
            self.register("user", UserMatrixGenerator(user_matrix))
            sources = ["user"]

        all_items = []
        for src_name in sources:
            self._ensure_registered(src_name)
            gen = self._generators.get(src_name)
            if not gen:
                continue
            items = await gen.generate(
                protocol="udp_voice", state_db=state_db,
                domain=domain, scan_level=scan_level,
                max_count=max_count // len(sources) or max_count,
                run_set=None,
            )
            all_items.extend(items)

        seen: set[str] = set()
        deduped: list[StrategyItem] = []
        for item in all_items:
            if item.strategy in seen:
                continue
            seen.add(item.strategy)
            deduped.append(item)
        return deduped[:max_count]

    async def generate_pairs(self,
                              tcp_sources: list[str] = None,
                              udp_sources: list[str] = None,
                              domain: str = "discord.com",
                              scan_level: str = "fast",
                              max_tcp: int = 100,
                              max_udp: int = 50,
                              state_db: StateDB = None,
                              user_matrix: str = "",
                              ) -> list[StrategyPair]:
        """Generate TCP×UDP strategy pairs with prioritization.

        Priority ordering:
          1. Known working TCP × working UDP (from state.db)
          2. New strategies from generators
          3. Known FAIL (deprioritized, tested last)
        """
        tcp_items = await self.generate_tcp(
            sources=tcp_sources, domain=domain,
            scan_level=scan_level, max_count=max_tcp,
            state_db=state_db, user_matrix=user_matrix,
        )
        udp_items = await self.generate_udp(
            sources=udp_sources, domain=domain,
            scan_level=scan_level, max_count=max_udp,
            state_db=state_db, user_matrix=user_matrix,
        )

        # Get known working from state.db
        known_tcp = []
        if state_db:
            known_tcp = await state_db.get_working_tcp(domain)

        # Build pairs with priority
        pairs = []
        for tcp in tcp_items:
            for udp in udp_items:
                pair = StrategyPair(tcp=tcp, udp=udp)
                pairs.append(pair)

        # Sort: working TCP first, then unknown, then fail
        return sorted(pairs, key=lambda p: (
            0 if p.tcp.label in known_tcp else 1,
            p.tcp.label,
            p.udp.label,
        ))
