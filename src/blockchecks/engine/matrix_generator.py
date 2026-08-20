"""Combine generator sources into TCP, UDP, HTTP, and QUIC strategy lists."""

from __future__ import annotations

import inspect
import logging
from typing import TYPE_CHECKING

from blockchecks.engine.byedpi_matrix_generator import ByedpiMatrixGenerator
from blockchecks.engine.family_registry import prune_items_by_triage
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

if TYPE_CHECKING:
    from blockchecks.engine.triage import TriageProfile

log = logging.getLogger(__name__)


async def _call_generate(gen: StrategyGenerator, **kwargs):
    """Pass only kwargs the generator's ``generate()`` accepts."""
    sig = inspect.signature(gen.generate)
    if any(p.kind is p.VAR_KEYWORD for p in sig.parameters.values()):
        return await gen.generate(**kwargs)
    accepted = {k: v for k, v in kwargs.items() if k in sig.parameters}
    return await gen.generate(**accepted)


def _dedupe(items: list[StrategyItem], max_count: int) -> list[StrategyItem]:
    seen: set[str] = set()
    out: list[StrategyItem] = []
    for item in items:
        if item.strategy in seen:
            continue
        seen.add(item.strategy)
        out.append(item)
    return out[:max_count]


class MatrixGenerator:
    """Orchestrates multiple strategy sources with SCANLEVEL + state.db."""

    REGISTRY = {
        "custom": CustomListGenerator,
        "flowseal": FlowsealGenerator,
        "byedpi": ByedpiMatrixGenerator,
        "standard": lambda: StandardGenerator(strategy_types=list(TCP_FAMILIES)),
        "standard_udp": lambda: StandardGenerator(strategy_types=list(UDP_VOICE_FAMILIES)),
        "standard_udp_game": lambda: StandardGenerator(strategy_types=["udp_game"]),
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
        triage: TriageProfile | None = None,
    ) -> list[StrategyItem]:
        """Generate TCP strategies from specified sources."""
        if not sources:
            sources = ["custom", "configs", "standard"]

        if user_matrix:
            self.register("user", UserMatrixGenerator(user_matrix))
            sources = ["user"]

        import time as _time

        all_items = []
        for src_name in sources:
            self._ensure_registered(src_name)
            gen = self._generators.get(src_name)
            if not gen:
                continue
            t1 = _time.perf_counter()
            items = await _call_generate(
                gen,
                protocol=protocol,
                state_db=state_db,
                domain=domain,
                scan_level=scan_level,
                max_count=max_count // len(sources) or max_count,
                run_set=run_set,
                triage=triage,
            )
            dt = _time.perf_counter() - t1
            log.info("%s", f"    {src_name:20s} {len(items):5d} items  ({dt:.1f}s)")
            all_items.extend(items)

        return prune_items_by_triage(_dedupe(all_items, max_count), triage, scan_level=scan_level)

    async def generate_http(
        self,
        sources: list[str] | None = None,
        domain: str = "discord.com",
        scan_level: str = "fast",
        max_count: int = 50,
        state_db: RunStateStore = None,
        user_matrix: str = "",
        run_set: set = None,
        triage: TriageProfile | None = None,
    ) -> list[StrategyItem]:
        """Generate HTTP :80 strategies."""
        if triage is not None and triage.http_blocked is False:
            return []
        return await self.generate_tcp(
            sources=sources or ["custom", "standard_http"],
            domain=domain,
            scan_level=scan_level,
            max_count=max_count,
            state_db=state_db,
            protocol="http",
            user_matrix=user_matrix,
            run_set=run_set,
            triage=triage,
        )

    async def generate_udp(
        self,
        sources: list[str] = None,
        domain: str = "discord.com",
        scan_level: str = "fast",
        max_count: int = 50,
        state_db: RunStateStore = None,
        user_matrix: str = "",
        triage: TriageProfile | None = None,
    ) -> list[StrategyItem]:
        """Generate UDP strategies."""
        import time as _time

        if triage is not None and triage.voice_ok and not triage.udp_blocked:
            return []

        if not sources:
            sources = ["custom", "standard_udp"]

        if user_matrix:
            self.register("user", UserMatrixGenerator(user_matrix))
            sources = ["user"]

        # Map "standard" on the UDP path to the voice-only source;
        # "game" is the explicit non-Discord UDP pool (not in defaults).
        remap = {"standard": "standard_udp", "game": "standard_udp_game"}
        sources = [remap.get(s, s) for s in sources]
        proto_by_src = {"standard_udp_game": "udp_game"}

        all_items = []
        for src_name in sources:
            self._ensure_registered(src_name)
            gen = self._generators.get(src_name)
            if not gen:
                continue
            proto = proto_by_src.get(src_name, "udp_voice")
            t1 = _time.perf_counter()
            items = await _call_generate(
                gen,
                protocol=proto,
                state_db=state_db,
                domain=domain,
                scan_level=scan_level,
                max_count=max_count // len(sources) or max_count,
                run_set=None,
                triage=triage,
            )
            dt = _time.perf_counter() - t1
            log.info("%s", f"    {src_name:20s} {len(items):5d} items  ({dt:.1f}s)")
            all_items.extend(items)

        for item in all_items:
            if item.protocol != "udp_voice":
                item.protocol = "udp_voice"
        return prune_items_by_triage(_dedupe(all_items, max_count), triage, scan_level=scan_level)

    async def generate_quic(
        self,
        sources: list[str] | None = None,
        domain: str = "discord.com",
        scan_level: str = "fast",
        max_count: int = 50,
        state_db: RunStateStore = None,
        user_matrix: str = "",
        run_set: set = None,
        triage: TriageProfile | None = None,
    ) -> list[StrategyItem]:
        """Generate HTTP/3 QUIC strategies."""
        import time as _time

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
            t1 = _time.perf_counter()
            items = await _call_generate(
                gen,
                protocol="quic",
                state_db=state_db,
                domain=domain,
                scan_level=scan_level,
                max_count=max_count // len(sources) or max_count,
                run_set=run_set,
                triage=triage,
            )
            dt = _time.perf_counter() - t1
            log.info("%s", f"    {src_name:20s} {len(items):5d} items  ({dt:.1f}s)")
            all_items.extend(items)

        for item in all_items:
            if item.protocol != "quic":
                item.protocol = "quic"
        return prune_items_by_triage(_dedupe(all_items, max_count), triage, scan_level=scan_level)

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
        triage: TriageProfile | None = None,
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
            triage=triage,
        )
        udp_items = await self.generate_udp(
            sources=udp_sources,
            domain=domain,
            scan_level=scan_level,
            max_count=max_udp,
            state_db=state_db,
            user_matrix=user_matrix,
            triage=triage,
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
