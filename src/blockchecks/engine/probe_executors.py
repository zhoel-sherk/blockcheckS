"""TCP/UDP/QUIC single-probe executors for AsyncTestRunner."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Protocol

from blockchecks.engine.matrix_generator import StrategyItem
from blockchecks.engine.probe_result_logger import ProbeResultLogger
from blockchecks.engine.results import TcpTestResult, UdpTestResult
from blockchecks.engine.settle_profile import SettleProfile
from blockchecks.engine.wssize_retry import WSSIZE_RETRY
from blockchecks.terminal import RESET, YELLOW

if TYPE_CHECKING:
    from blockchecks.checkers.dns_secure import DnsRunCache
    from blockchecks.service.netns_pool import NetNsPool


class _TcpRunnerHost(Protocol):
    python: str
    disable_ech: bool
    secure_dns: bool
    dns_cache: DnsRunCache | None
    dns_audit: dict
    repeats: int
    parallel_repeats: bool
    repeats_mode: str
    quick_break: bool
    try_wssize: bool
    settle_profile: SettleProfile | None
    _timing_override_logged: set[str]


class _QuicRunnerHost(Protocol):
    python: str
    secure_dns: bool
    dns_cache: DnsRunCache | None
    dns_audit: dict


class _UdpRunnerHost(Protocol):
    python: str


log = logging.getLogger(__name__)


def _run_tcp_check(*args, **kwargs):
    from blockchecks.engine.async_runner import _run_tcp_check as fn

    return fn(*args, **kwargs)


def _run_tcp_check_multi(*args, **kwargs):
    from blockchecks.engine.async_runner import _run_tcp_check_multi as fn

    return fn(*args, **kwargs)


def _run_udp_check(*args, **kwargs):
    from blockchecks.engine.async_runner import _run_udp_check as fn

    return fn(*args, **kwargs)


def _run_quic_check(*args, **kwargs):
    from blockchecks.engine.async_runner import _run_quic_check as fn

    return fn(*args, **kwargs)


def _quic_fallback_variants(strategy: str):
    from blockchecks.engine.async_runner import _quic_fallback_variants as fn

    return fn(strategy)


def _is_quic_dropped(error: str) -> bool:
    from blockchecks.engine.async_runner import _is_quic_dropped as fn

    return fn(error)


class TcpProbeExecutor:
    """Single-domain and multi-domain TCP probes in pooled netns."""

    def __init__(
        self,
        runner: _TcpRunnerHost,
        pool: NetNsPool,
        semaphore: asyncio.Semaphore,
        result_logger: ProbeResultLogger,
    ) -> None:
        self._runner = runner
        self.pool = pool
        self.semaphore = semaphore
        self._result_logger = result_logger

    def timing_for(self, item: StrategyItem, timeout: float) -> tuple[float, float | None]:
        """Return (curl_timeout, settle_max override) from B11 profile if set."""
        cli_timeout = timeout
        settle_max: float | None = None
        profile = self._runner.settle_profile
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
        logged = self._runner._timing_override_logged

        if explicit_key is not None:
            if explicit_key not in logged:
                logged.add(explicit_key)
                log.info(
                    "settle profile override: strategy=%r settle_max=%s curl_timeout=%s source=%s",
                    snippet,
                    settle_max,
                    timeout,
                    source_path,
                )
        elif item.strategy.strip() not in logged:
            logged.add(item.strategy.strip())
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

    async def resolve_domain_dns(self, domain: str) -> tuple[str | None, str, str]:
        resolved_ip = None
        dns_verdict = ""
        doh_server = ""
        if self._runner.secure_dns and self._runner.dns_cache:
            resolved_ip = self._runner.dns_cache.primary_ip(domain)
            audit = self._runner.dns_audit.get(domain)
            if audit:
                dns_verdict = audit.verdict
                doh_server = audit.doh_server or self._runner.dns_cache.doh_server
        return resolved_ip, dns_verdict, doh_server

    def resolve_domain_ips(self, domain: str) -> list[str]:
        """Full candidate IP list for retry-on-next-IP (pinned first)."""
        if self._runner.dns_cache:
            try:
                return self._runner.dns_cache.resolve(domain)
            except Exception as exc:
                log.warning("%s", f"  WARNING: DNS resolve failed for {domain} ({exc})")
        return []

    def tcp_result_from_data(self, item: StrategyItem, domain: str, data: dict) -> TcpTestResult:
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
        # result.success stays HTTP for diagnostics; AQ/harvest use campaign_pass().
        return result

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
        await self._result_logger.log_tcp_result(
            item,
            domain,
            result,
            resolved_ip=resolved_ip,
            dns_verdict=dns_verdict,
            doh_server=doh_server,
        )

    async def test_tcp(
        self, item: StrategyItem, domain: str, timeout: float = 5.0
    ) -> TcpTestResult:
        """Test one TCP strategy in an isolated netns."""
        runner = self._runner
        result = TcpTestResult(item=item, domain=domain)
        timeout, settle_max = self.timing_for(item, timeout)

        async with self.semaphore:
            ns_name = await self.pool.acquire()
            try:
                resolved_ip = None
                dns_verdict = ""
                doh_server = ""
                if runner.secure_dns and runner.dns_cache:
                    resolved_ip = runner.dns_cache.primary_ip(domain)
                    audit = runner.dns_audit.get(domain)
                    if audit:
                        dns_verdict = audit.verdict
                        doh_server = audit.doh_server or runner.dns_cache.doh_server
                protocol = getattr(item, "protocol", "tls12") or "tls12"
                ip_candidates = self.resolve_domain_ips(domain)
                data = await asyncio.to_thread(
                    _run_tcp_check,
                    ns_name,
                    item.strategy,
                    domain,
                    timeout,
                    item.is_config,
                    runner.python,
                    runner.disable_ech,
                    resolved_ip,
                    runner.repeats,
                    runner.parallel_repeats,
                    "",
                    protocol,
                    settle_max,
                    None,
                    runner.repeats_mode,
                    runner.quick_break,
                    resolved_ips=ip_candidates,
                )
                if WSSIZE_RETRY.should_retry(
                    data,
                    try_wssize=runner.try_wssize,
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
                        runner.python,
                        runner.disable_ech,
                        resolved_ip,
                        runner.repeats,
                        runner.parallel_repeats,
                        WSSIZE_RETRY.cmd,
                        protocol,
                        settle_max,
                        None,
                        runner.repeats_mode,
                        runner.quick_break,
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
        runner = self._runner
        results: list[TcpTestResult] = []
        timeout, settle_max = self.timing_for(item, timeout)
        async with self.semaphore:
            ns_name = await self.pool.acquire()
            try:
                resolved_ips: dict[str, str | None] = {}
                resolved_ip_lists: dict[str, list[str]] = {}
                dns_meta: dict[str, tuple[str, str]] = {}
                for domain in domains:
                    rip, dv, ds = await self.resolve_domain_dns(domain)
                    resolved_ips[domain] = rip
                    resolved_ip_lists[domain] = self.resolve_domain_ips(domain)
                    dns_meta[domain] = (dv, ds)
                protocol = getattr(item, "protocol", "tls12") or "tls12"
                data_map = await asyncio.to_thread(
                    _run_tcp_check_multi,
                    ns_name,
                    item.strategy,
                    domains,
                    timeout,
                    is_config=item.is_config,
                    python_bin=runner.python,
                    disable_ech=runner.disable_ech,
                    resolved_ips=resolved_ips,
                    resolved_ip_lists=resolved_ip_lists,
                    repeats=runner.repeats,
                    extra_lua_desync="",
                    protocol=protocol,
                    curl_parallel=curl_parallel,
                    settle_max=settle_max,
                    parallel_repeats=runner.parallel_repeats,
                    repeats_mode=runner.repeats_mode,
                    quick_break=runner.quick_break,
                )
                for domain in domains:
                    data = data_map.get(domain, {})
                    if WSSIZE_RETRY.should_retry(
                        data,
                        try_wssize=runner.try_wssize,
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
                            runner.python,
                            runner.disable_ech,
                            resolved_ips.get(domain),
                            runner.repeats,
                            runner.parallel_repeats,
                            WSSIZE_RETRY.cmd,
                            protocol,
                            settle_max,
                            None,
                            runner.repeats_mode,
                            runner.quick_break,
                            resolved_ips=resolved_ip_lists.get(domain),
                        )
                    result = self.tcp_result_from_data(item, domain, data)
                    rip = resolved_ips.get(domain)
                    dv, ds = dns_meta.get(domain, ("", ""))
                    await self.log_tcp_result(
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


class QuicProbeExecutor:
    """QUIC/HTTP3 strategy probes in pooled netns."""

    def __init__(
        self,
        runner: _QuicRunnerHost,
        pool: NetNsPool,
        semaphore: asyncio.Semaphore,
        result_logger: ProbeResultLogger,
    ) -> None:
        self._runner = runner
        self.pool = pool
        self.semaphore = semaphore
        self._result_logger = result_logger

    async def test_quic(
        self, item: StrategyItem, domain: str, timeout: float = 8.0
    ) -> TcpTestResult:
        """Test one QUIC/HTTP3 strategy in an isolated netns."""
        runner = self._runner
        result = TcpTestResult(item=item, domain=domain)

        async with self.semaphore:
            ns_name = await self.pool.acquire()
            try:
                resolved_ip = None
                dns_verdict = ""
                doh_server = ""
                if runner.secure_dns and runner.dns_cache:
                    resolved_ip = runner.dns_cache.primary_ip(domain)
                    audit = runner.dns_audit.get(domain)
                    if audit:
                        dns_verdict = audit.verdict
                        doh_server = audit.doh_server or runner.dns_cache.doh_server

                variants = [item.strategy] + _quic_fallback_variants(item.strategy)
                for idx, variant in enumerate(variants):
                    variant_timeout = timeout if idx == 0 else min(timeout, 3.0)
                    data = await asyncio.to_thread(
                        _run_quic_check,
                        ns_name,
                        variant,
                        domain,
                        variant_timeout,
                        item.is_config,
                        runner.python,
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


class UdpProbeExecutor:
    """UDP strategy probes in pooled netns."""

    def __init__(
        self,
        runner: _UdpRunnerHost,
        pool: NetNsPool,
        semaphore: asyncio.Semaphore,
        result_logger: ProbeResultLogger,
    ) -> None:
        self._runner = runner
        self.pool = pool
        self.semaphore = semaphore
        self._result_logger = result_logger

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
                    self._runner.python,
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
