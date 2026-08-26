"""Persist TCP/UDP/QUIC probe rows to RunStateStore and data_block."""

from __future__ import annotations

from blockchecks.engine.matrix_generator import StrategyItem
from blockchecks.engine.results import TcpTestResult, UdpTestResult
from blockchecks.engine.store import RunStateStore
from blockchecks.service.batch_service import PROBE_SKIP_ERRORS


def tcp_row_status(result: TcpTestResult) -> str:
    if result.error in PROBE_SKIP_ERRORS:
        return "SKIPPED"
    if result.throttled:
        return "THROTTLED"
    if result.success:
        return "PASS"
    return "FAIL"


def resolved_ip_for_log(used_ip: str, resolved_ip: str | None) -> str:
    return used_ip if used_ip else (resolved_ip or "")


class ProbeResultLogger:
    """Write probe outcomes to sqlite and optional data_block exports."""

    def __init__(self, db: RunStateStore | None) -> None:
        self.db = db

    async def log_tcp_probe(
        self,
        item: StrategyItem,
        domain: str,
        result: TcpTestResult,
        *,
        resolved_ip: str | None,
        dns_verdict: str,
        doh_server: str,
        save_data_block: bool = False,
    ) -> None:
        if not self.db:
            return
        protocol = getattr(item, "protocol", "tls12") or "tls12"
        proto_db = "http" if protocol == "http" else "tcp"
        await self.db.log_tcp(
            item.label,
            domain,
            tcp_row_status(result),
            result.latency_ms,
            result.http_code,
            content_valid=result.content_valid,
            error=result.error,
            read_rate_bps=result.read_rate_bps,
            config_path=item.strategy,
            resolved_ip=resolved_ip_for_log(result.used_ip, resolved_ip),
            dns_verdict=dns_verdict,
            doh_server=doh_server,
            proto=proto_db,
            probe_host=getattr(result, "probe_host", "") or "",
        )
        if save_data_block and result.success:
            await _save_pass_data_block(
                item.strategy,
                domain,
                protocol=proto_db,
                latency_ms=result.latency_ms,
                http_code=result.http_code,
            )

    async def log_tcp_result(
        self,
        item: StrategyItem,
        domain: str,
        result: TcpTestResult,
        *,
        resolved_ip: str | None,
        dns_verdict: str,
        doh_server: str,
    ) -> None:
        if not self.db:
            return
        protocol = getattr(item, "protocol", "tls12") or "tls12"
        proto_db = "http" if protocol == "http" else "tcp"
        status = tcp_row_status(result)
        await self.db.log_tcp(
            item.label,
            domain,
            status,
            result.latency_ms,
            result.http_code,
            content_valid=result.content_valid,
            error=result.error,
            read_rate_bps=result.read_rate_bps,
            config_path=item.strategy,
            resolved_ip=resolved_ip_for_log(result.used_ip, resolved_ip),
            dns_verdict=dns_verdict,
            doh_server=doh_server,
            proto=proto_db,
            fail_phase=result.fail_phase,
            bridge_applied=result.bridge_applied,
            bridge_batch_id=result.bridge_batch_id,
            bridge_gen=result.bridge_gen,
            probe_host=getattr(result, "probe_host", "") or "",
        )
        if status == "PASS":
            await _save_pass_data_block(
                item.strategy,
                domain,
                protocol=proto_db,
                latency_ms=result.latency_ms,
                http_code=result.http_code,
            )

    async def log_quic_result(
        self,
        item: StrategyItem,
        domain: str,
        result: TcpTestResult,
        *,
        resolved_ip: str | None,
        dns_verdict: str,
        doh_server: str,
    ) -> None:
        if not self.db:
            return
        await self.db.log_tcp(
            item.label,
            domain,
            "PASS" if result.success else "FAIL",
            result.latency_ms,
            result.http_code,
            content_valid=True,
            error=result.error,
            config_path=item.strategy,
            resolved_ip=resolved_ip or "",
            dns_verdict=dns_verdict,
            doh_server=doh_server,
            proto="quic",
            probe_host=getattr(result, "probe_host", "") or "",
        )

    async def log_udp_result(
        self,
        item: StrategyItem,
        target: str,
        result: UdpTestResult,
    ) -> None:
        if self.db:
            await self.db.log_udp(
                item.label,
                target,
                "PASS" if result.success else "FAIL",
                result.latency_ms,
                result.error,
                config_path=item.strategy,
            )
        if result.success:
            await _save_pass_data_block(
                item.strategy,
                target,
                protocol="udp",
                latency_ms=result.latency_ms,
                http_code=0,
            )


async def _save_pass_data_block(
    strategy: str,
    domain: str,
    *,
    protocol: str,
    latency_ms: float,
    http_code: int,
) -> None:
    from blockchecks.engine import async_runner

    await async_runner._save_pass_strategy_data_block(
        strategy,
        domain,
        protocol=protocol,
        latency_ms=latency_ms,
        http_code=http_code,
    )
