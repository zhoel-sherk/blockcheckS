"""Result models for strategy tests (TcpTestResult / UdpTestResult / PairResult).

Split out of the async_runner god-file (day-5 refactor) so the models can be
imported without pulling in the whole network/worker machinery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from blockchecks.engine.generators.base import StrategyItem


@dataclass
class TcpTestResult:
    item: StrategyItem
    domain: str
    success: bool = False
    http_code: int = 0
    latency_ms: float = 0
    content_length: int = 0
    content_valid: bool = True
    throttled: bool = False
    read_rate_bps: float = 0
    error: str = ""
    used_ip: str = ""
    fail_phase: str = ""


def tcp_results_from_details(
    by_label: dict[str, StrategyItem],
    details: list[dict],
    domain: str,
) -> list[TcpTestResult]:
    """Build TcpTestResult list from get_working_tcp_details rows (PASS/THROTTLED)."""
    out: list[TcpTestResult] = []
    for d in details:
        item = by_label.get(d["name"])
        if item is None:
            continue
        out.append(
            TcpTestResult(
                item=item,
                domain=domain,
                success=True,
                throttled=d.get("status") == "THROTTLED",
                latency_ms=float(d.get("latency_ms") or 0),
            )
        )
    return out


@dataclass
class UdpTestResult:
    item: StrategyItem
    target: str
    success: bool = False
    latency_ms: float = 0
    error: str = ""


@dataclass
class PairResult:
    tcp_item: StrategyItem
    udp_item: StrategyItem
    tcp_ok: bool = False
    udp_ok: bool = False
    tcp_ms: float = 0
    udp_ms: float = 0
    overall: str = "PENDING"


@dataclass
class ScanReport:
    domain: str
    tcp_results: list = field(default_factory=list)
    pairs: list = field(default_factory=list)
    total_time_sec: float = 0
    voice_info: dict = field(default_factory=dict)
