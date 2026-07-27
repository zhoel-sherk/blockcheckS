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

from engine.db_logger import StateDB


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
                        max_count: int = 100) -> list[StrategyItem]:
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
                        max_count: int = 100) -> list[StrategyItem]:
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
        return items[:max_count]


# ── Config file generator (blockcheckS/configs/ .conf files) ──

class ConfigFileGenerator(StrategyGenerator):
    """Load pre-built .conf files."""

    def __init__(self, config_dir: str = "configs"):
        self.config_dir = config_dir

    async def generate(self, protocol: str = "tls12",
                        state_db: StateDB = None,
                        domain: str = "",
                        scan_level: str = "fast",
                        max_count: int = 100) -> list[StrategyItem]:
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
        return items[:max_count]


# ── Standard generators (hardcoded from blockcheck2.d/standard/*.sh) ──

# Fooling options mapped from def.inc
FOOLINGS_TCP = [
    "",
    "tcp_md5",
    "tcp_ts=-1000",
    "tcp_ack=-66000:tcp_ts_up",
]
REPEATS_VALUES = [6, 3, 1, 10, 12]  # 6 first — known working on Fryazino
TTL_VALUES = [1, 5, 7, 12]
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
                        max_count: int = 100) -> list[StrategyItem]:
        items = []
        known_working = []

        if state_db and domain:
            known_working = await state_db.get_working_tcp(domain)

        for blob in BLOBS_TCP:
            blob_part = f":blob={blob}" if blob else ""
            for repeats in REPEATS_VALUES:
                for fool in FOOLINGS_TCP:
                    fool_part = _fooling_clause(fool)
                    # Base strategy (no TTL) — test first
                    strat = f"fake{blob_part}:repeats={repeats}{fool_part}"
                    label = f"fake_{blob or 'none'}_r{repeats}_{fool or 'nofool'}"
                    items.append(StrategyItem(label=label, strategy=strat))
                    if len(items) >= max_count:
                        return items[:max_count]

                    # SCANLEVEL: if base works, skip TTL variations
                    if scan_level == "fast" and label in known_working:
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
                        max_count: int = 100) -> list[StrategyItem]:
        items = []
        known_working = []
        if state_db and domain:
            known_working = await state_db.get_working_tcp(domain)

        for fool in ["", "tcp_md5", "tcp_ts=-1000", "tcp_ack=-66000:tcp_ts_up"]:
            fool_part = _fooling_clause(fool)
            # Base
            strat = f"hostfakesplit:nofake2{fool_part}:repeats=1"
            label = f"hf_nofake2_{fool or 'nofool'}"
            items.append(StrategyItem(label=label, strategy=strat))

            if scan_level == "fast" and label in known_working:
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
                        max_count: int = 100) -> list[StrategyItem]:
        items = []
        for pos in [1, "midsld", "sniext+1"]:
            for fool in ["", "tcp_md5", "tcp_ts=-1000"]:
                fool_part = _fooling_clause(fool)
                strat = f"multisplit:pos={pos}:seqovl=1{fool_part}"
                label = f"faked_p{pos}_{fool or 'nofool'}"
                items.append(StrategyItem(label=label, strategy=strat))
                if len(items) >= max_count:
                    return items[:max_count]
        return items[:max_count]


class FakeMultiGenerator(StrategyGenerator):
    """Multi-blob fake (2-3 blobs simultaneously)."""

    async def generate(self, protocol: str = "tls12",
                        state_db: StateDB = None,
                        domain: str = "",
                        scan_level: str = "fast",
                        max_count: int = 100) -> list[StrategyItem]:
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
                    if len(items) >= max_count:
                        return items[:max_count]
        return items[:max_count]


class FakeSplitComboGenerator(StrategyGenerator):
    """fake + fakedsplit combined."""

    async def generate(self, protocol: str = "tls12",
                        state_db: StateDB = None,
                        domain: str = "",
                        scan_level: str = "fast",
                        max_count: int = 100) -> list[StrategyItem]:
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
                        max_count: int = 100) -> list[StrategyItem]:
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
        return items[:max_count]


# ── Orchestrator ──

class MatrixGenerator:
    """Orchestrates multiple strategy sources with SCANLEVEL + state.db."""

    REGISTRY = {
        "custom": CustomListGenerator,
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
            )
            all_items.extend(items)

        return all_items[:max_count]

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
            )
            all_items.extend(items)

        return all_items[:max_count]

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
