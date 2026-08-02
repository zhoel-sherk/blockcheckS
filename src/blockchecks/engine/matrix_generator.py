"""Strategy matrix generator — combinatorial strategy generation.

Facade over engine.generators.*. See docs/architecture.md.
"""

from blockchecks.engine.generators import (
    HTTP_FAMILIES,
    QUIC_HTTP3_FAMILIES,
    TCP_FAMILIES,
    UDP_VOICE_FAMILIES,
    ConfigFileGenerator,
    CustomListGenerator,
    FakedTcpGenerator,
    FakeMultiGenerator,
    FakeSplitComboGenerator,
    FakeTcpGenerator,
    FlowsealGenerator,
    HostfakeTcpGenerator,
    StandardGenerator,
    StrategyGenerator,
    StrategyItem,
    StrategyPair,
    UserMatrixGenerator,
)
from blockchecks.engine.store import RunStateStore


class MatrixGenerator:
    """Orchestrates multiple strategy sources with SCANLEVEL + state.db."""

    REGISTRY = {
        "custom": CustomListGenerator,
        "flowseal": FlowsealGenerator,
        "standard": lambda: StandardGenerator(strategy_types=list(TCP_FAMILIES)),
        "standard_udp": lambda: StandardGenerator(strategy_types=list(UDP_VOICE_FAMILIES)),
        "standard_quic": lambda: StandardGenerator(strategy_types=list(QUIC_HTTP3_FAMILIES)),
        "standard_http": lambda: StandardGenerator(strategy_types=list(HTTP_FAMILIES)),
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
            factory = self.REGISTRY[name]
            self._generators[name] = factory() if callable(factory) else factory

    async def generate_tcp(
        self,
        sources: list[str] = None,
        domain: str = "discord.com",
        scan_level: str = "fast",
        max_count: int = 100,
        state_db: RunStateStore = None,
        protocol: str = "tls12",
        user_matrix: str = "",
        run_set: set = None,
    ) -> list[StrategyItem]:
        """Generate TCP strategies from specified sources."""
        if not sources:
            sources = ["custom", "configs", "standard"]

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
                protocol=protocol,
                state_db=state_db,
                domain=domain,
                scan_level=scan_level,
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

    async def generate_http(
        self,
        sources: list[str] | None = None,
        domain: str = "discord.com",
        scan_level: str = "fast",
        max_count: int = 50,
        state_db: RunStateStore = None,
        user_matrix: str = "",
        run_set: set = None,
    ) -> list[StrategyItem]:
        """Generate HTTP :80 strategies (BC2-9)."""
        return await self.generate_tcp(
            sources=sources or ["custom", "standard_http"],
            domain=domain,
            scan_level=scan_level,
            max_count=max_count,
            state_db=state_db,
            protocol="http",
            user_matrix=user_matrix,
            run_set=run_set,
        )

    async def generate_udp(
        self,
        sources: list[str] = None,
        domain: str = "discord.com",
        scan_level: str = "fast",
        max_count: int = 50,
        state_db: RunStateStore = None,
        user_matrix: str = "",
    ) -> list[StrategyItem]:
        """Generate UDP strategies."""
        if not sources:
            sources = ["custom", "standard_udp"]

        if user_matrix:
            self.register("user", UserMatrixGenerator(user_matrix))
            sources = ["user"]

        # Map legacy "standard" on UDP path to voice-only source
        sources = ["standard_udp" if s == "standard" else s for s in sources]

        all_items = []
        for src_name in sources:
            self._ensure_registered(src_name)
            gen = self._generators.get(src_name)
            if not gen:
                continue
            proto = "udp_voice"
            items = await gen.generate(
                protocol=proto,
                state_db=state_db,
                domain=domain,
                scan_level=scan_level,
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

    async def generate_quic(
        self,
        sources: list[str] | None = None,
        domain: str = "discord.com",
        scan_level: str = "fast",
        max_count: int = 50,
        state_db: RunStateStore = None,
        user_matrix: str = "",
        run_set: set = None,
    ) -> list[StrategyItem]:
        """Generate HTTP/3 QUIC strategies (BC2-10)."""
        if not sources:
            sources = ["custom", "standard_quic"]

        if user_matrix:
            self.register("user", UserMatrixGenerator(user_matrix))
            sources = ["user"]

        all_items: list[StrategyItem] = []
        for src_name in sources:
            self._ensure_registered(src_name)
            gen = self._generators.get(src_name)
            if not gen:
                continue
            items = await gen.generate(
                protocol="quic",
                state_db=state_db,
                domain=domain,
                scan_level=scan_level,
                max_count=max_count // len(sources) or max_count,
                run_set=run_set,
            )
            all_items.extend(items)

        seen: set[str] = set()
        deduped: list[StrategyItem] = []
        for item in all_items:
            if item.strategy in seen:
                continue
            seen.add(item.strategy)
            if item.protocol != "quic":
                item.protocol = "quic"
            deduped.append(item)
        return deduped[:max_count]

    async def generate_pairs(
        self,
        tcp_sources: list[str] = None,
        udp_sources: list[str] = None,
        domain: str = "discord.com",
        scan_level: str = "fast",
        max_tcp: int = 100,
        max_udp: int = 50,
        state_db: RunStateStore = None,
        user_matrix: str = "",
    ) -> list[StrategyPair]:
        """Generate TCP×UDP strategy pairs with prioritization.

        Priority ordering:
          1. Known working TCP × working UDP (from state.db)
          2. New strategies from generators
          3. Known FAIL (deprioritized, tested last)
        """
        tcp_items = await self.generate_tcp(
            sources=tcp_sources,
            domain=domain,
            scan_level=scan_level,
            max_count=max_tcp,
            state_db=state_db,
            user_matrix=user_matrix,
        )
        udp_items = await self.generate_udp(
            sources=udp_sources,
            domain=domain,
            scan_level=scan_level,
            max_count=max_udp,
            state_db=state_db,
            user_matrix=user_matrix,
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
        return sorted(
            pairs,
            key=lambda p: (
                0 if p.tcp.label in known_tcp else 1,
                p.tcp.label,
                p.udp.label,
            ),
        )
