"""Parallel strategy tests.
Each job uses a pooled netns. curl_cffi runs in a worker thread (libcurl is not async).
"""

import asyncio
import logging
import os

from blockchecks.checkers.dns_secure import DnsRunCache
from blockchecks.engine.config import BLOB_DIR, PYTHON_BIN  # noqa: F401
from blockchecks.engine.dns_pin_service import DnsPinService, pin_candidate_l3_ok
from blockchecks.engine.matrix_generator import StrategyItem
from blockchecks.engine.pair_matrix_runner import PairMatrixRunner
from blockchecks.engine.probe_executors import (
    QuicProbeExecutor,
    TcpProbeExecutor,
    UdpProbeExecutor,
)
from blockchecks.engine.probe_result_logger import (
    ProbeResultLogger,
    resolved_ip_for_log,
    tcp_row_status,
)
from blockchecks.engine.settle_profile import SettleProfile
from blockchecks.engine.store import RunStateStore
from blockchecks.service.batch_models import BatchContext, BatchProbeConfig, RunnerProbeDeps
from blockchecks.service.batch_scheduler import BatchScheduler
from blockchecks.service.batch_service import ProbeBatchService
from blockchecks.service.in_ns_workers import RETRY_IP_TIMEOUT  # noqa: F401
from blockchecks.service.netns_pool import NetNsPool
from blockchecks.service.nfqws2 import start_daemon as _nfqws2_daemon  # noqa: F401
from blockchecks.terminal import status_tag

log = logging.getLogger(__name__)

_pin_candidate_l3_ok = pin_candidate_l3_ok

from blockchecks.engine.conf_builder import add_blobs_from_strategy, split_cli_args
from blockchecks.engine.nfqws_config import (  # noqa: F401
    _build_inline_nfqws_lines,
    _build_quic_nfqws_lines,
    _sudo,
)
from blockchecks.engine.results import (
    PairResult,
    ScanReport,
    TcpTestResult,
    UdpTestResult,
    tcp_results_from_details,
)
from blockchecks.service.in_ns_workers import (
    _is_quic_dropped,  # noqa: F401 — re-export for tests / lazy workers
    _quic_fallback_variants,  # noqa: F401
    _run_quic_check,  # noqa: F401
    _run_tcp_check,
    _run_tcp_check_multi,  # noqa: F401
    _run_udp_check,  # noqa: F401
    _save_pass_strategy_data_block,  # noqa: F401
)

__all__ = [
    "AsyncTestRunner",
    "CampaignProbeResultLogger",
    "PairResult",
    "ScanReport",
    "StrategyItem",
    "TcpTestResult",
    "UdpTestResult",
    "campaign_harvest_status",
    "tcp_results_from_details",
]

_tcp_row_status = tcp_row_status

# Backward-compat module aliases (not in __all__).
_add_blobs_from_strategy = add_blobs_from_strategy
_split_cli_args = split_cli_args

_PROBE_BACKEND_LUA = "lua_bridge"
_PROBE_BACKEND_ONESHOT = "oneshot"


def campaign_harvest_status(result: TcpTestResult, backend: str) -> str:
    """SQLite status for campaign rows; harvest counts only lua_bridge APPLIED PASS."""
    base = tcp_row_status(result)
    if base != "PASS":
        return base
    if backend == _PROBE_BACKEND_LUA:
        return "PASS" if result.success and result.bridge_applied is True else "FAIL"
    if backend == _PROBE_BACKEND_ONESHOT:
        return "FAIL"
    log.warning("campaign harvest: unknown probe backend %r — demoting PASS", backend)
    return "FAIL"


def _campaign_fail_phase(result: TcpTestResult, backend: str, status: str) -> str:
    phase = result.fail_phase or ""
    if status == "PASS":
        return phase
    if backend == _PROBE_BACKEND_ONESHOT and result.success:
        return phase or _PROBE_BACKEND_ONESHOT
    if backend == _PROBE_BACKEND_LUA and result.success and result.bridge_applied is not True:
        return phase or "no_bridge_applied"
    return phase


class CampaignProbeResultLogger(ProbeResultLogger):
    """Gates DB PASS: lua_bridge needs APPLIED; oneshot never writes harvest PASS."""

    def __init__(self, db: RunStateStore | None) -> None:
        super().__init__(db)
        self._probe_backend = _PROBE_BACKEND_LUA

    def set_probe_backend(self, backend: str) -> None:
        self._probe_backend = backend

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
        await self._log_tcp_campaign(
            item,
            domain,
            result,
            backend=self._probe_backend,
            resolved_ip=resolved_ip,
            dns_verdict=dns_verdict,
            doh_server=doh_server,
            save_data_block=True,
        )

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
        await self._log_tcp_campaign(
            item,
            domain,
            result,
            backend=_PROBE_BACKEND_ONESHOT,
            resolved_ip=resolved_ip,
            dns_verdict=dns_verdict,
            doh_server=doh_server,
            save_data_block=save_data_block,
        )

    async def _log_tcp_campaign(
        self,
        item: StrategyItem,
        domain: str,
        result: TcpTestResult,
        *,
        backend: str,
        resolved_ip: str | None,
        dns_verdict: str,
        doh_server: str,
        save_data_block: bool,
    ) -> None:
        if not self.db:
            return
        protocol = getattr(item, "protocol", "tls12") or "tls12"
        proto_db = "http" if protocol == "http" else "tcp"
        status = campaign_harvest_status(result, backend)
        fail_phase = _campaign_fail_phase(result, backend, status)
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
            fail_phase=fail_phase,
            bridge_applied=result.bridge_applied,
            bridge_batch_id=result.bridge_batch_id,
            bridge_gen=result.bridge_gen,
            probe_host=getattr(result, "probe_host", "") or "",
            settle_ms=getattr(result, "settle_ms", None),
            content_len=result.content_length,
        )
        if save_data_block and status == "PASS":
            from blockchecks.engine.probe_result_logger import _save_pass_data_block

            await _save_pass_data_block(
                item.strategy,
                domain,
                protocol=proto_db,
                latency_ms=result.latency_ms,
                http_code=result.http_code,
            )


class AsyncTestRunner:
    """Parallel strategy tester using NetNsPool + asyncio.Semaphore."""

    def __init__(
        self,
        pool_size: int = 4,
        db: RunStateStore = None,
        python_path: str = None,
        disable_ech: bool = False,
        secure_dns: bool = True,
        dns_cache: DnsRunCache | None = None,
        dns_audit: dict | None = None,
        pinned_path: str | None = None,
        auto_pin: bool = True,
        repeats: int = 1,
        parallel_repeats: bool = False,
        repeats_mode: str = "fast",
        quick_break: bool = False,
        try_wssize: bool = False,
        settle_profile: SettleProfile | None = None,
        lua_bridge: bool = True,
        bridge_batch: int = 500,
        lua_extra: list[str] | None = None,
        netns_base: str | None = None,
    ):
        from blockchecks.engine.config import NETNS_BASE

        self.pool = NetNsPool(
            size=pool_size,
            base=netns_base or f"{NETNS_BASE}-{os.getpid() % 10000:04d}",
        )
        self.semaphore = asyncio.Semaphore(pool_size)
        self.db = db
        self.python = python_path or PYTHON_BIN
        self.matrix_fingerprint: str = ""
        self.disable_ech = disable_ech
        self.secure_dns = secure_dns
        self.dns_cache = dns_cache
        self.dns_audit = dns_audit or {}
        self.pinned_path = pinned_path or ""
        self.auto_pin = auto_pin
        from blockchecks.checkers.curl_probe import clamp_repeats

        self.repeats = clamp_repeats(repeats)
        self.parallel_repeats = parallel_repeats
        self.repeats_mode = repeats_mode or "fast"
        self.quick_break = quick_break
        self.try_wssize = try_wssize
        self.settle_profile = settle_profile
        self._timing_override_logged: set[str] = set()
        self.lua_bridge = lua_bridge
        self.bridge_batch = max(1, bridge_batch)
        self.lua_extra = list(lua_extra or [])
        self._probe_gen = 0
        self._batch_id = 0
        self.memory_monitor = None
        self._result_logger = CampaignProbeResultLogger(db)
        self._dns_pin = (
            DnsPinService(
                dns_cache=dns_cache,
                pinned_path=self.pinned_path,
                python_path=self.python,
                disable_ech=self.disable_ech,
                acquire_ns=self.pool.acquire,
                release_ns=self.pool.release,
            )
            if dns_cache is not None
            else None
        )
        self._tcp_executor = TcpProbeExecutor(self, self.pool, self.semaphore, self._result_logger)
        self._quic_executor = QuicProbeExecutor(self, self.pool, self.semaphore, self._result_logger)
        self._udp_executor = UdpProbeExecutor(self, self.pool, self.semaphore, self._result_logger)
        self._pair_runner = PairMatrixRunner(
            self.pool,
            self.db,
            python=self.python,
            disable_ech=self.disable_ech,
            matrix_fingerprint=self.matrix_fingerprint,
        )

    def ensure_memory_monitor(self):
        """Lazily create the shared MemoryMonitor for bridge runs."""
        if self.memory_monitor is None:
            from blockchecks.service.metrics import MemoryMonitor

            self.memory_monitor = MemoryMonitor()
        return self.memory_monitor

    def _next_batch_id(self) -> int:
        self._batch_id += 1
        return self._batch_id

    def _make_probe_deps(self) -> RunnerProbeDeps:
        return RunnerProbeDeps(
            python=self.python,
            disable_ech=self.disable_ech,
            repeats=self.repeats,
            parallel_repeats=self.parallel_repeats,
            repeats_mode=self.repeats_mode,
            quick_break=self.quick_break,
            try_wssize=self.try_wssize,
            lua_extra=list(self.lua_extra),
            timing_for=self._timing_for,
            resolve_domain_dns=self._resolve_domain_dns,
            resolve_domain_ips=self._resolve_domain_ips,
            tcp_result_from_data=self._tcp_result_from_data,
            log_tcp_result=self._log_tcp_result,
            next_probe_gen=self._next_probe_gen,
            run_tcp_check=_run_tcp_check,
            acquire_ns=self.pool.acquire,
            release_ns=self.pool.release,
            secure_dns=bool(self.secure_dns),
        )

    def _probe_service(self, backend: str) -> ProbeBatchService:
        del backend
        return ProbeBatchService(
            BatchProbeConfig(
                backend="lua_bridge",
                batch_size=self.bridge_batch,
                lua_extra=tuple(self.lua_extra),
            ),
            self._make_probe_deps(),
            memory_monitor=self.ensure_memory_monitor(),
        )

    async def _run_probe_batch(
        self,
        items: list[StrategyItem],
        domain: str,
        timeout: float,
        backend: str,
        domains: list[str] | None = None,
        stop_event: asyncio.Event | None = None,
    ) -> list[TcpTestResult]:
        if not items:
            return []
        if stop_event is not None and stop_event.is_set():
            return []
        protocol = getattr(items[0], "protocol", "tls12") or "tls12"
        ctx = BatchContext(
            ns_name="",
            items=items,
            domain=domain,
            batch_id=self._next_batch_id(),
            protocol=protocol,
            domains=domains,
        )
        async with self.semaphore:
            result = await self._probe_service(backend).run_batch(ctx, timeout, stop_event)
        return list(result.results)

    def _next_probe_gen(self) -> int:
        self._probe_gen += 1
        return self._probe_gen

    def _timing_for(self, item: StrategyItem, timeout: float) -> tuple[float, float | None]:
        return self._tcp_executor.timing_for(item, timeout)

    async def start(self):
        """Create netns pool, seed the Queue, and auto-pin working IPs."""
        await asyncio.to_thread(self.pool.create_all)
        await self.pool.seed()
        if self.auto_pin and self._dns_pin is not None:
            await self._auto_pin_ips()

    async def _auto_pin_ips(self) -> None:
        if self._dns_pin is not None:
            import blockchecks.engine.async_runner as ar

            self._dns_pin.pinned_path = self.pinned_path
            await self._dns_pin.auto_pin_ips(
                probe=self._probe_pin_ip,
                l3_ok=ar._pin_candidate_l3_ok,
            )

    async def _probe_pin_ip(self, domain: str, ip: str) -> bool:
        if self._dns_pin is None:
            return False
        return await self._dns_pin.probe_pin_ip(domain, ip)

    async def stop(self):
        """Drain queue then destroy netns pool (kills persistent curl workers)."""
        from blockchecks.service.probe import release_curl_probe_worker

        for ns_name in list(self.pool._names):
            release_curl_probe_worker(ns_name)
        await self.pool.drain()
        await asyncio.to_thread(self.pool.destroy_all)

    async def test_tcp(
        self, item: StrategyItem, domain: str, timeout: float = 5.0
    ) -> TcpTestResult:
        """Test one TCP strategy in an isolated netns (oneshot backend)."""
        self._result_logger.set_probe_backend(_PROBE_BACKEND_ONESHOT)
        try:
            return await self._tcp_executor.test_tcp(item, domain, timeout=timeout)
        finally:
            self._result_logger.set_probe_backend(_PROBE_BACKEND_LUA)

    async def test_quic(
        self, item: StrategyItem, domain: str, timeout: float = 8.0
    ) -> TcpTestResult:
        """Test one QUIC/HTTP3 strategy in an isolated netns."""
        return await self._quic_executor.test_quic(item, domain, timeout=timeout)

    async def _resolve_domain_dns(self, domain: str) -> tuple[str | None, str, str]:
        return await self._tcp_executor.resolve_domain_dns(domain)

    def _resolve_domain_ips(self, domain: str) -> list[str]:
        return self._tcp_executor.resolve_domain_ips(domain)

    def _tcp_result_from_data(self, item: StrategyItem, domain: str, data: dict) -> TcpTestResult:
        return self._tcp_executor.tcp_result_from_data(item, domain, data)

    async def _log_tcp_result(
        self,
        item: StrategyItem,
        domain: str,
        result: TcpTestResult,
        *,
        resolved_ip: str | None,
        dns_verdict: str,
        doh_server: str,
    ) -> None:
        await self._tcp_executor.log_tcp_result(
            item,
            domain,
            result,
            resolved_ip=resolved_ip,
            dns_verdict=dns_verdict,
            doh_server=doh_server,
        )

    async def test_tcp_domains(
        self,
        item: StrategyItem,
        domains: list[str],
        timeout: float = 5.0,
        *,
        curl_parallel: int = 4,
    ) -> list[TcpTestResult]:
        """Fan-out: one nfqws2 session, parallel curl (oneshot — not harvest PASS)."""
        self._result_logger.set_probe_backend(_PROBE_BACKEND_ONESHOT)
        try:
            return await self._tcp_executor.test_tcp_domains(
                item, domains, timeout=timeout, curl_parallel=curl_parallel
            )
        finally:
            self._result_logger.set_probe_backend(_PROBE_BACKEND_LUA)

    async def test_udp(
        self, item: StrategyItem, ip: str, port: int, timeout: float = 3.0
    ) -> UdpTestResult:
        """Test one UDP strategy."""
        return await self._udp_executor.test_udp(item, ip, port, timeout=timeout)

    async def test_batch_tcp(
        self, strategies: list[StrategyItem], domain: str, timeout: float = 5.0
    ) -> list[TcpTestResult]:
        """Parallel batch of TCP strategy tests (lua_bridge, results in input order)."""
        if not strategies:
            return []
        return await self._test_batch_tcp_bridge(strategies, domain, timeout)

    async def _test_batch_tcp_bridge(
        self, strategies: list[StrategyItem], domain: str, timeout: float = 5.0
    ) -> list[TcpTestResult]:
        scheduler = BatchScheduler(self.bridge_batch)
        batches = scheduler.iter_batches(strategies)
        if not batches:
            return []
        nested = await asyncio.gather(
            *(self._run_probe_batch(batch, domain, timeout, "lua_bridge") for batch in batches)
        )
        all_results = [r for batch_out in nested for r in batch_out]
        self._print_tcp_batch_results(all_results)
        return all_results

    def _print_tcp_batch_results(self, results: list[TcpTestResult]) -> None:
        for r in results:
            tag = status_tag(r.success, throttled=r.throttled)
            lat = f"{r.latency_ms:.0f}ms" if r.latency_ms else ""
            status = f"HTTP {r.http_code}" if r.http_code else ""
            err = f" — {r.error[:40]}" if r.error else ""
            label = r.item.label[:30]
            log.info("%s", f"  [{tag}] {lat:>6s}  {status:>8s}  {label}{err}")

    async def test_pair_matrix(
        self,
        tcp_results: list[TcpTestResult],
        udp_strategies: list[StrategyItem],
        domain: str,
        voice_ip: str,
        voice_port: int,
        udp_timeout: float = 3.0,
        udp_bypass: bool = False,
        resume_from=None,
        full_voice: bool = False,
        fingerprint: str = "",
        *,
        pair_domain: str | None = None,
    ) -> list[PairResult]:
        """Parallel UDP probes for each PASS TCP × each UDP strategy."""
        self._pair_runner.matrix_fingerprint = self.matrix_fingerprint
        return await self._pair_runner.run(
            tcp_results,
            udp_strategies,
            domain,
            voice_ip,
            voice_port,
            udp_timeout=udp_timeout,
            udp_bypass=udp_bypass,
            resume_from=resume_from,
            full_voice=full_voice,
            fingerprint=fingerprint,
            pair_domain=pair_domain,
        )

    @staticmethod
    def print_matrix(pairs: list[PairResult]):
        """Print colored pair matrix to console."""
        PairMatrixRunner.print_matrix(pairs)
