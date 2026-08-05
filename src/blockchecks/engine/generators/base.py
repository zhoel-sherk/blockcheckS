"""Strategy matrix types and base generator."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from blockchecks.engine.store import RunStateStore


@dataclass
class StrategyItem:
    label: str
    strategy: str
    is_config: bool = False
    protocol: str = "tls12"  # tls12 | tls13 | http


@dataclass
class StrategyPair:
    tcp: StrategyItem
    udp: StrategyItem


# ── Base class ──


class StrategyGenerator(ABC):
    @abstractmethod
    async def generate(
        self,
        protocol: str = "tls12",
        state_db: RunStateStore = None,
        domain: str = "",
        scan_level: str = "fast",
        max_count: int = 100,
        run_set: set = None,
    ) -> list[StrategyItem]: ...
