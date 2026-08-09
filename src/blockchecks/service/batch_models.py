"""Batch probe data models — config, context, result and runner deps."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from blockchecks.engine.generators.base import StrategyItem

ProbeBackend = Literal["classic", "lua_bridge"]


@dataclass(frozen=True)
class BatchContext:
    ns_name: str
    items: list
    domain: str
    batch_id: int
    protocol: str = "tls12"
    domains: list[str] | None = None  # parallel to items; defaults to domain

    def item_domains(self) -> list[str]:
        if self.domains is not None and len(self.domains) == len(self.items):
            return list(self.domains)
        return [self.domain] * len(self.items)


@dataclass(frozen=True)
class BatchProbeConfig:
    backend: ProbeBackend
    batch_size: int = 500
    lua_extra: tuple[str, ...] = ()
    compare_classic: bool = False


@dataclass
class BatchProbeResult:
    results: list
    settle_ms: float = 0.0
    batch_wall_ms: float = 0.0
    backend: str = "classic"
    batch_fill_ratio: float = 1.0


@dataclass
class RunnerProbeDeps:
    """Minimal runner contract for ProbeBatchService (avoids cyclic imports)."""

    python: str
    disable_ech: bool
    repeats: int
    parallel_repeats: bool
    repeats_mode: str
    quick_break: bool
    try_wssize: bool
    lua_extra: list[str]
    timing_for: Callable[[StrategyItem, float], tuple[float, float | None]]
    resolve_domain_dns: Callable[[str], Awaitable[tuple[str | None, str, str]]]
    tcp_result_from_data: Callable[[StrategyItem, str, dict], object]
    log_tcp_result: Callable[..., Awaitable[None]]
    next_probe_gen: Callable[[], int]
    run_tcp_check: Callable[..., dict]
    acquire_ns: Callable[[], Awaitable[str]]
    release_ns: Callable[[str], Awaitable[None]]
