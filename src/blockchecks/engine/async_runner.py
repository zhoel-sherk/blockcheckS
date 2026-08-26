"""Parallel strategy tests.
Each job uses a pooled netns. curl_cffi runs in a worker thread (libcurl is not async).
"""

import asyncio
import logging
import os

from blockchecks.checkers.dns_secure import DnsRunCache
from blockchecks.engine.config import BLOB_DIR, PYTHON_BIN  # noqa: F401
from blockchecks.engine.dns_pin_service import DnsPinService, pin_candidate_l3_ok
from blockchecks.engine.in_ns_workers import RETRY_IP_TIMEOUT  # noqa: F401
from blockchecks.engine.matrix_generator import StrategyItem
from blockchecks.engine.probe_result_logger import ProbeResultLogger, tcp_row_status
from blockchecks.engine.settle_profile import SettleProfile
from blockchecks.engine.store import RunStateStore
from blockchecks.service.batch_models import BatchContext, BatchProbeConfig, RunnerProbeDeps
from blockchecks.service.batch_scheduler import BatchScheduler
from blockchecks.service.batch_service import ProbeBatchService
from blockchecks.service.netns_pool import NetNsPool
from blockchecks.service.nfqws2 import start_daemon as _nfqws2_daemon  # noqa: F401
from blockchecks.terminal import CYAN, GREEN, RED, RESET, YELLOW, status_tag

log = logging.getLogger(__name__)

_pin_candidate_l3_ok = pin_candidate_l3_ok

from blockchecks.engine.conf_builder import add_blobs_from_strategy, split_cli_args
from blockchecks.engine.in_ns_workers import (
    _is_quic_dropped,
    _quic_fallback_variants,
    _run_quic_check,
    _run_tcp_check,
    _run_tcp_check_multi,
    _run_udp_check,
    _save_pass_strategy_data_block,
)
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
from blockchecks.engine.wssize_retry import WSSIZE_RETRY

__all__ = [
    "AsyncTestRunner",
    "PairResult",
    "ScanReport",
    "StrategyItem",
    "TcpTestResult",
    "UdpTestResult",
    "tcp_results_from_details",
]

_tcp_row_status = tcp_row_status

# Private names kept as aliases.
_add_blobs_from_strategy = add_blobs_from_strategy
_split_cli_args = split_cli_args


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
        lua_bridge: bool = False,
        bridge_batch: int = 500,
        lua_bridge_compare: bool = False,
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
        self.lua_bridge_compare = lua_bridge_compare
        self.lua_extra = list(lua_extra or [])
        self._probe_gen = 0
        self._batch_id = 0
        self.memory_monitor = None
        self._result_logger = ProbeResultLogger(db)
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
        )

    def _probe_service(self, backend: str) -> ProbeBatchService:
        monitor = self.memory_monitor
        if backend == "lua_bridge":
            monitor = self.ensure_memory_monitor()
        return ProbeBatchService(
            BatchProbeConfig(
                backend=backend,
                batch_size=self.bridge_batch,
                lua_extra=tuple(self.lua_extra),
            ),
            self._make_probe_deps(),
            memory_monitor=monitor,
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
        """Return (curl_timeout, settle_max override) from B11 profile if set."""
        cli_timeout = timeout
        settle_max: float | None = None
        profile = self.settle_profile
        if profile is None:
            return timeout, settle_max

        override = profile.lookup(item.strategy)
        if override is None:
            return timeout, settle_max

        settle_max = override.settle_max
        if override.curl_timeout is not None:
            timeout = override.curl_timeout

        source_path = profile.source_path or "?"
        explicit_key = profile.match_key(item.strategy)
        snippet = (explicit_key or item.strategy.strip())[:80]

        if explicit_key is not None:
            if explicit_key not in self._timing_override_logged:
                self._timing_override_logged.add(explicit_key)
                log.info(
                    "settle profile override: strategy=%r settle_max=%s curl_timeout=%s source=%s",
                    snippet,
                    settle_max,
                    timeout,
                    source_path,
                )
        elif item.strategy.strip() not in self._timing_override_logged:
            self._timing_override_logged.add(item.strategy.strip())
            log.warning(
                "settle profile defaults fallback: strategy=%r settle_max=%s "
                "curl_timeout=%s cli_timeout=%s source=%s",
                snippet,
                settle_max,
                timeout,
                cli_timeout,
                source_path,
            )
        return timeout, settle_max

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
        """Drain queue then destroy netns pool."""
        await self.pool.drain()
        await asyncio.to_thread(self.pool.destroy_all)

    async def test_tcp(
        self, item: StrategyItem, domain: str, timeout: float = 5.0
    ) -> TcpTestResult:
        """Test one TCP strategy in an isolated netns."""
        result = TcpTestResult(item=item, domain=domain)
        timeout, settle_max = self._timing_for(item, timeout)

        async with self.semaphore:
            ns_name = await self.pool.acquire()
            try:
                resolved_ip = None
                dns_verdict = ""
                doh_server = ""
                if self.secure_dns and self.dns_cache:
                    resolved_ip = self.dns_cache.primary_ip(domain)
                    audit = self.dns_audit.get(domain)
                    if audit:
                        dns_verdict = audit.verdict
                        doh_server = audit.doh_server or self.dns_cache.doh_server
                protocol = getattr(item, "protocol", "tls12") or "tls12"
                ip_candidates = self._resolve_domain_ips(domain)
                data = await asyncio.to_thread(
                    _run_tcp_check,
                    ns_name,
                    item.strategy,
                    domain,
                    timeout,
                    item.is_config,
                    self.python,
                    self.disable_ech,
                    resolved_ip,
                    self.repeats,
                    self.parallel_repeats,
                    "",
                    protocol,
                    settle_max,
                    None,
                    self.repeats_mode,
                    self.quick_break,
                    resolved_ips=ip_candidates,
                )
                if WSSIZE_RETRY.should_retry(
                    data,
                    try_wssize=self.try_wssize,
                    protocol=protocol,
                    strategy=item.strategy,
                    is_config=item.is_config,
                ):
                    data = await asyncio.to_thread(
                        _run_tcp_check,
                        ns_name,
                        item.strategy,
                        domain,
                        WSSIZE_RETRY.retry_timeout(timeout),
                        item.is_config,
                        self.python,
                        self.disable_ech,
                        resolved_ip,
                        self.repeats,
                        self.parallel_repeats,
                        WSSIZE_RETRY.cmd,
                        protocol,
                        settle_max,
                        None,
                        self.repeats_mode,
                        self.quick_break,
                        resolved_ips=ip_candidates,
                    )
                result.success = data.get("success", False)
                result.http_code = data.get("http_code", 0)
                result.latency_ms = data.get("latency_ms", 0)
                result.content_length = data.get("content_len", 0)
                result.content_valid = data.get("content_ok", True)
                result.throttled = data.get("throttled", False)
                result.read_rate_bps = data.get("read_rate_bps", 0)
                result.used_ip = data.get("used_ip") or ""
                result.probe_host = data.get("resolve_name") or ""
                result.error = data.get("error", "") or ""

                await self._result_logger.log_tcp_probe(
                    item,
                    domain,
                    result,
                    resolved_ip=resolved_ip,
                    dns_verdict=dns_verdict,
                    doh_server=doh_server,
                )
            except Exception as e:
                result.error = str(e)[:200]
            finally:
                await self.pool.release(ns_name)

        return result

    async def test_quic(
        self, item: StrategyItem, domain: str, timeout: float = 8.0
    ) -> TcpTestResult:
        """Test one QUIC/HTTP3 strategy in an isolated netns."""
        result = TcpTestResult(item=item, domain=domain)

        async with self.semaphore:
            ns_name = await self.pool.acquire()
            try:
                resolved_ip = None
                dns_verdict = ""
                doh_server = ""
                if self.secure_dns and self.dns_cache:
                    resolved_ip = self.dns_cache.primary_ip(domain)
                    audit = self.dns_audit.get(domain)
                    if audit:
                        dns_verdict = audit.verdict
                        doh_server = audit.doh_server or self.dns_cache.doh_server

                variants = [item.strategy] + _quic_fallback_variants(item.strategy)
                for idx, variant in enumerate(variants):
                    # Base strategy uses the full timeout; fallback variants are
                    # quick drop-checks — a TSPU drop happens immediately, so a
                    # shorter budget avoids 3× wall time when everything drops.
                    variant_timeout = timeout if idx == 0 else min(timeout, 3.0)
                    data = await asyncio.to_thread(
                        _run_quic_check,
                        ns_name,
                        variant,
                        domain,
                        variant_timeout,
                        item.is_config,
                        self.python,
                        resolved_ip,
                    )
                    result.success = data.get("success", False)
                    result.http_code = data.get("http_code", 0)
                    result.latency_ms = data.get("latency_ms", 0)
                    result.content_length = data.get("content_len", 0)
                    result.error = data.get("error", "") or ""
                    result.probe_host = data.get("resolve_name") or ""
                    if result.success or not _is_quic_dropped(result.error):
                        break
                    # timeout = TSPU dropped this variant; try the next fallback.
                    if variant != variants[-1]:
                        log.info(
                            "%s",
                            f"  {YELLOW}[quic] {item.label[:24]} timeout "
                            f"— trying fallback: {variant[:40]}...{RESET}",
                        )

                await self._result_logger.log_quic_result(
                    item,
                    domain,
                    result,
                    resolved_ip=resolved_ip,
                    dns_verdict=dns_verdict,
                    doh_server=doh_server,
                )
            except Exception as e:
                result.error = str(e)[:200]
            finally:
                await self.pool.release(ns_name)

        return result

    async def _resolve_domain_dns(self, domain: str) -> tuple[str | None, str, str]:
        resolved_ip = None
        dns_verdict = ""
        doh_server = ""
        if self.secure_dns and self.dns_cache:
            resolved_ip = self.dns_cache.primary_ip(domain)
            audit = self.dns_audit.get(domain)
            if audit:
                dns_verdict = audit.verdict
                doh_server = audit.doh_server or self.dns_cache.doh_server
        return resolved_ip, dns_verdict, doh_server

    def _resolve_domain_ips(self, domain: str) -> list[str]:
        """Full candidate IP list for retry-on-next-IP (pinned first)."""
        if self.dns_cache:
            try:
                return self.dns_cache.resolve(domain)
            except Exception as exc:
                log.warning("%s", f"  WARNING: DNS resolve failed for {domain} ({exc})")
        return []

    def _tcp_result_from_data(self, item: StrategyItem, domain: str, data: dict) -> TcpTestResult:
        result = TcpTestResult(item=item, domain=domain)
        result.success = data.get("success", False)
        result.http_code = data.get("http_code", 0)
        result.latency_ms = data.get("latency_ms", 0)
        result.content_length = data.get("content_len", 0)
        result.content_valid = data.get("content_ok", True)
        result.throttled = data.get("throttled", False)
        result.read_rate_bps = data.get("read_rate_bps", 0)
        result.error = data.get("error", "") or ""
        result.used_ip = data.get("used_ip") or ""
        result.probe_host = data.get("resolve_name") or ""
        result.rst_in_ttl = int(data.get("bridge_rst_in_ttl") or 0)
        ba = data.get("bridge_applied")
        result.bridge_applied = None if ba is None else bool(ba)
        result.bridge_batch_id = int(data.get("batch_id") or 0)
        result.bridge_gen = int(data.get("bridge_gen") or 0)
        if data.get("bridge_rst_in") and not result.success:
            # DPI injected a RST after the SNI was seen (scan_bridge detector).
            from blockchecks.engine.fail_phase import FailPhase

            result.fail_phase = FailPhase.TLS_RST_AT_SNI.value
        elif result.error and not result.success:
            from blockchecks.engine.fail_phase import classify_fail_phase

            result.fail_phase = classify_fail_phase(result.error, result.http_code).value
        if "bridge_applied" in data and data.get("bridge_applied") is False and result.success:
            tail = data.get("bridge_raw_tail") or ""
            log.warning(
                "%s",
                f"  {YELLOW}WARN: bridge PASS without APPLIED event for "
                f"{item.label[:24]} (strategy may not have been picked up by nfqws2)"
                f"{(' raw=[' + tail + ']') if tail else ''}{RESET}",
            )
        return result

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
        await self._result_logger.log_tcp_result(
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
        """B2: one nfqws2 session, parallel curl for multiple domains."""
        if not domains:
            return []
        results: list[TcpTestResult] = []
        timeout, settle_max = self._timing_for(item, timeout)
        async with self.semaphore:
            ns_name = await self.pool.acquire()
            try:
                resolved_ips: dict[str, str | None] = {}
                resolved_ip_lists: dict[str, list[str]] = {}
                dns_meta: dict[str, tuple[str, str]] = {}
                for domain in domains:
                    rip, dv, ds = await self._resolve_domain_dns(domain)
                    resolved_ips[domain] = rip
                    resolved_ip_lists[domain] = self._resolve_domain_ips(domain)
                    dns_meta[domain] = (dv, ds)
                protocol = getattr(item, "protocol", "tls12") or "tls12"
                data_map = await asyncio.to_thread(
                    _run_tcp_check_multi,
                    ns_name,
                    item.strategy,
                    domains,
                    timeout,
                    is_config=item.is_config,
                    python_bin=self.python,
                    disable_ech=self.disable_ech,
                    resolved_ips=resolved_ips,
                    resolved_ip_lists=resolved_ip_lists,
                    repeats=self.repeats,
                    extra_lua_desync="",
                    protocol=protocol,
                    curl_parallel=curl_parallel,
                    settle_max=settle_max,
                    parallel_repeats=self.parallel_repeats,
                    repeats_mode=self.repeats_mode,
                    quick_break=self.quick_break,
                )
                for domain in domains:
                    data = data_map.get(domain, {})
                    if WSSIZE_RETRY.should_retry(
                        data,
                        try_wssize=self.try_wssize,
                        protocol=protocol,
                        strategy=item.strategy,
                        is_config=item.is_config,
                    ):
                        data = await asyncio.to_thread(
                            _run_tcp_check,
                            ns_name,
                            item.strategy,
                            domain,
                            WSSIZE_RETRY.retry_timeout(timeout),
                            item.is_config,
                            self.python,
                            self.disable_ech,
                            resolved_ips.get(domain),
                            self.repeats,
                            self.parallel_repeats,
                            WSSIZE_RETRY.cmd,
                            protocol,
                            settle_max,
                            None,
                            self.repeats_mode,
                            self.quick_break,
                            resolved_ips=resolved_ip_lists.get(domain),
                        )
                    result = self._tcp_result_from_data(item, domain, data)
                    rip = resolved_ips.get(domain)
                    dv, ds = dns_meta.get(domain, ("", ""))
                    await self._log_tcp_result(
                        item, domain, result, resolved_ip=rip, dns_verdict=dv, doh_server=ds
                    )
                    results.append(result)
            except Exception as e:
                for domain in domains:
                    if not any(r.domain == domain for r in results):
                        err = TcpTestResult(item=item, domain=domain, error=str(e)[:200])
                        results.append(err)
            finally:
                await self.pool.release(ns_name)
        return results

    async def test_udp(
        self, item: StrategyItem, ip: str, port: int, timeout: float = 3.0
    ) -> UdpTestResult:
        """Test one UDP strategy."""
        target = f"{ip}:{port}"
        result = UdpTestResult(item=item, target=target)

        async with self.semaphore:
            ns_name = await self.pool.acquire()
            try:
                data = await asyncio.to_thread(
                    _run_udp_check,
                    ns_name,
                    item.strategy,
                    ip,
                    port,
                    timeout,
                    item.is_config,
                    self.python,
                )
                result.success = data.get("success", False)
                result.latency_ms = data.get("latency_ms", 0)
                result.error = data.get("detail", "") or ""

                await self._result_logger.log_udp_result(item, target, result)
            except Exception as e:
                result.error = str(e)[:200]
            finally:
                await self.pool.release(ns_name)

        return result

    async def test_batch_tcp(
        self, strategies: list[StrategyItem], domain: str, timeout: float = 5.0
    ) -> list[TcpTestResult]:
        """Parallel batch of TCP strategy tests (results in input order)."""
        if not strategies:
            return []

        if self.lua_bridge_compare:
            classic = await self._test_batch_tcp_classic(strategies, domain, timeout)
            bridge = await self._test_batch_tcp_bridge(strategies, domain, timeout)
            for c, b in zip(classic, bridge, strict=False):
                if c.success != b.success or c.http_code != b.http_code:
                    log.info(
                        "%s",
                        f"  {RED}BRIDGE_COMPARE drift: {c.item.label[:24]} "
                        f"classic={c.success}/{c.http_code} bridge={b.success}/{b.http_code}{RESET}",
                    )
            return bridge

        if self.lua_bridge:
            return await self._test_batch_tcp_bridge(strategies, domain, timeout)

        return await self._test_batch_tcp_classic(strategies, domain, timeout)

    async def _test_batch_tcp_classic(
        self, strategies: list[StrategyItem], domain: str, timeout: float = 5.0
    ) -> list[TcpTestResult]:
        if not strategies:
            return []
        scheduler = BatchScheduler(self.bridge_batch)
        batches = scheduler.iter_batches(strategies)
        nested = await asyncio.gather(
            *(self._run_probe_batch(batch, domain, timeout, "classic") for batch in batches)
        )
        all_results = [r for batch_out in nested for r in batch_out]
        self._print_tcp_batch_results(all_results)
        return all_results

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
        """Parallel UDP probes for each PASS TCP × each UDP strategy.

        Each pair runs in its own netns via asyncio.create_task + Semaphore.
        TCP nfqws2 started once per pair, UDP nfqws2 per strategy.
        DB writes serialized via asyncio.Lock.

        ``pair_domain`` overrides the domain key used for pair_results /
        resume (e.g. ``discord.com@1.2.3.4:50004`` for multi-EP fan-out);
        TCP curl still uses ``domain``.
        """
        from blockchecks.engine.store.models import Checkpoint

        pairs: list[PairResult] = []
        db_lock = asyncio.Lock()
        pair_sem = asyncio.Semaphore(self.pool.size)
        fp = fingerprint or self.matrix_fingerprint
        log_domain = pair_domain or domain

        if udp_bypass:
            working = list(enumerate(tcp_results))
        else:
            working = [(i, r) for i, r in enumerate(tcp_results) if r.success]

        if not working:
            log.info("%s", f"\n  {RED}No PASS TCP — UDP skipped{RESET}")
            return pairs

        total = len(working) * len(udp_strategies)

        # Resume: skip only pairs already in DB (completed-set).
        # Checkpoint idx is NOT used for skip — parallel pairs make idx a non-frontier.
        completed: set[tuple[str, str]] = set()
        if self.db:
            try:
                completed = await self.db.get_completed_pair_keys(log_domain)
            except Exception as exc:
                log.warning("%s", f"  WARNING: pair resume keys unavailable ({exc})")
                completed = set()
        if isinstance(resume_from, Checkpoint) and resume_from.tcp_label:
            log.info(
                "%s",
                f"  {YELLOW}Resuming after "
                f"{resume_from.tcp_label}+{resume_from.udp_label} "
                f"({len(completed)} pairs in DB){RESET}",
            )
        elif resume_from is not None and getattr(resume_from, "tcp_label", None):
            log.info(
                "%s",
                f"  {YELLOW}Resuming after "
                f"{resume_from.tcp_label}+{getattr(resume_from, 'udp_label', '')} "
                f"({len(completed)} pairs in DB){RESET}",
            )
        elif completed:
            log.info("%s", f"  {YELLOW}Resuming: {len(completed)} pairs already in DB{RESET}")
        ep_tag = f" ep={voice_ip}:{voice_port}" if pair_domain else ""
        log.info(
            "%s",
            f"  {CYAN}Pair matrix: {len(working)} TCP × {len(udp_strategies)} UDP "
            f"= {total} pairs, {self.pool.size} parallel{ep_tag}{RESET}",
        )

        async def run_pair(tcp_i: int, tcp_r: TcpTestResult, udp_s: StrategyItem, pair_idx: int):
            key = (tcp_r.item.label, udp_s.label)
            if key in completed:
                return
            async with pair_sem:
                ns_name = await self.pool.acquire()
                try:
                    await asyncio.to_thread(
                        _run_tcp_check,
                        ns_name,
                        tcp_r.item.strategy,
                        domain,
                        0.1,
                        tcp_r.item.is_config,
                        self.python,
                        self.disable_ech,
                    )
                    data = await asyncio.to_thread(
                        _run_udp_check,
                        ns_name,
                        udp_s.strategy,
                        voice_ip,
                        voice_port,
                        udp_timeout,
                        udp_s.is_config,
                        self.python,
                        True,  # coexist — keep TCP nfqws2 (qnum 200) alive
                    )
                    udp_ok = data.get("success", False)
                    udp_ms = data.get("latency_ms", 0)

                    pair = PairResult(
                        tcp_item=tcp_r.item,
                        udp_item=udp_s,
                        tcp_ok=tcp_r.success,
                        udp_ok=udp_ok,
                        tcp_ms=tcp_r.latency_ms,
                        udp_ms=udp_ms,
                    )
                    if tcp_r.throttled and udp_ok:
                        pair.overall = "THROTTLED"
                    elif tcp_r.success and udp_ok:
                        pair.overall = "PASS"
                    elif tcp_r.success and not udp_ok:
                        pair.overall = "PARTIAL"
                    else:
                        pair.overall = "FAIL"

                    pairs.append(pair)

                    pair_tag = {
                        "PASS": f"{GREEN}PASS{RESET}",
                        "PARTIAL": f"{YELLOW}PARTIAL{RESET}",
                        "THROTTLED": f"{YELLOW}THROTTLED{RESET}",
                        "FAIL": f"{RED}FAIL{RESET}",
                    }[pair.overall]
                    udp_tag = f"{GREEN}{udp_ms:.0f}ms{RESET}" if udp_ok else f"{RED}timeout{RESET}"
                    voice_tag = " [voice]" if full_voice else ""
                    log.info(
                        "%s",
                        f"  [{pair_tag}] {tcp_r.item.label[:22]:22s} "
                        f"+ {udp_s.label[:22]:22s}  udp={udp_tag}{voice_tag}",
                    )

                    if udp_ok:
                        await _save_pass_strategy_data_block(
                            udp_s.strategy,
                            f"{voice_ip}:{voice_port}",
                            protocol="udp",
                            latency_ms=udp_ms,
                            http_code=0,
                        )
                    if self.db:
                        async with db_lock:
                            await self.db.log_udp(
                                udp_s.label,
                                f"{voice_ip}:{voice_port}",
                                "PASS" if udp_ok else "FAIL",
                                udp_ms,
                                data.get("detail", "") or "",
                                config_path=udp_s.strategy,
                            )
                            await self.db.log_pair(
                                tcp_r.item.label,
                                udp_s.label,
                                log_domain,
                                tcp_r.success,
                                False,
                                udp_ok,
                                tcp_r.latency_ms,
                                0,
                                udp_ms,
                                pair.overall,
                            )
                            await self.db.save_checkpoint(
                                tcp_i,
                                pair_idx,
                                f"{tcp_r.item.label}+{udp_s.label}@{voice_ip}:{voice_port}",
                                fingerprint=fp,
                                tcp_label=tcp_r.item.label,
                                udp_label=udp_s.label,
                            )
                finally:
                    await self.pool.release(ns_name)

        tasks = []
        for tcp_i, tcp_r in working:
            for udp_ord, udp_s in enumerate(udp_strategies):
                tasks.append(asyncio.create_task(run_pair(tcp_i, tcp_r, udp_s, udp_ord)))

        for res in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(res, BaseException):
                log.error("%s", f"  {RED}pair task error: {type(res).__name__}: {res}{RESET}")
        return pairs

    # Matrix display

    @staticmethod
    def print_matrix(pairs: list[PairResult]):
        """Print colored pair matrix to console."""
        if not pairs:
            return
        tcp_names = sorted(set(p.tcp_item.label for p in pairs))
        udp_names = sorted(set(p.udp_item.label for p in pairs))
        pair_map = {f"{p.tcp_item.label}|{p.udp_item.label}": p for p in pairs}

        log.info("%s", f"\n  {CYAN}╔{'═' * 60}╗{RESET}")
        log.info("%s", f"  {CYAN}║{'TCP×UDP Pair Matrix':^60s}║{RESET}")

        passed = 0
        for tcp in tcp_names:
            for udp in udp_names:
                p = pair_map.get(f"{tcp}|{udp}")
                if not p:
                    continue
                if p.overall == "PASS":
                    passed += 1
                    tag = f"{GREEN}PASS{RESET}"
                elif p.overall in ("PARTIAL", "THROTTLED"):
                    tag = f"{YELLOW}{p.overall}{RESET}"
                else:
                    tag = f"{RED}FAIL{RESET}"
                udp_lat = f"{p.udp_ms:.0f}ms" if p.udp_ok else "timeout"
                log.info("%s", f"  {tag:12s} {tcp[:22]:22s} + {udp[:22]:22s}  udp={udp_lat}")

        log.info("%s", f"  {CYAN}{'═' * 60}{RESET}")
        log.info("%s", f"  {GREEN}{passed} PASS{RESET} / {len(pairs)} pairs")
