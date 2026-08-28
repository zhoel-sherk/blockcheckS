"""TcpTestResult, UdpTestResult, PairResult."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from blockchecks.engine.generators.base import StrategyItem


def campaign_pass(*, http_ok: bool, bridge_applied: bool | None) -> bool:
    """Campaign/AQ pass: bridge requires APPLIED; oneshot (``None``) uses HTTP only."""
    match bridge_applied:
        case True:
            return http_ok
        case False:
            return False
        case None:
            return http_ok


@dataclass
class TcpTestResult:
    item: StrategyItem
    domain: str
    success: bool = False
    http_code: int = 0
    latency_ms: float = 0
    settle_ms: float | None = None
    content_length: int = 0
    content_valid: bool = True
    throttled: bool = False
    read_rate_bps: float = 0
    error: str = ""
    used_ip: str = ""
    # SNI, которым реально зондиовали (для googlevideo — хост из GGC-пула).
    probe_host: str = ""
    fail_phase: str = ""
    rst_in_ttl: int = 0
    # Lua-bridge provenance: None = unknown (classic/QUIC paths),
    # True = APPLIED event seen, False = PASS without APPLIED (suspicious).
    bridge_applied: bool | None = None
    bridge_batch_id: int = 0
    bridge_gen: int = 0

    def campaign_pass(self) -> bool:
        return campaign_pass(http_ok=self.success, bridge_applied=self.bridge_applied)


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
