"""Async parallel test runner — builds on NetNsPool for concurrent DPI tests.

Each test runs in its own pre-created netns from the pool.
curl_cffi is called via asyncio.to_thread() (libcurl is C, not async).
"""

import asyncio
import os

from colorama import Fore, Style
from colorama import init as colorama_init

colorama_init(autoreset=True)

from blockchecks.checkers.dns_secure import DnsRunCache
from blockchecks.engine.config import (
    BLOB_DIR,
    PIN_TIMEOUT,
    PYTHON_BIN,
)
from blockchecks.engine.in_ns_workers import RETRY_IP_TIMEOUT
from blockchecks.engine.matrix_generator import StrategyItem
from blockchecks.engine.settle_profile import SettleProfile
from blockchecks.engine.store import RunStateStore
from blockchecks.service.batch_models import BatchContext, BatchProbeConfig, RunnerProbeDeps
from blockchecks.service.batch_scheduler import BatchScheduler
from blockchecks.service.batch_service import ProbeBatchService
from blockchecks.service.netns_pool import NetNsPool
from blockchecks.service.nfqws2 import start_daemon as _nfqws2_daemon

GREEN = Fore.GREEN + Style.BRIGHT
RED = Fore.RED + Style.BRIGHT
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
GREY = Fore.LIGHTBLACK_EX
RESET = Style.RESET_ALL

# Auto-pin (IP-PIN): known-good strategy + short budget for probing candidate
# IPs at startup. Pinned IPs override DoH order against per-IP throttling.
PIN_STRATEGY = "fake:blob=stun:repeats=6:tcp_ts=-1000"
PIN_SETTLE_MAX = 0.5
# Budget for retry-on-next-IP attempts after the first failed IP (keeps
# throttled-IP worst case from N×timeout, see per-IP throttling).

from blockchecks.engine.in_ns_workers import (
    _is_quic_dropped,
    _quic_fallback_variants,
    _run_quic_check,
    _run_tcp_check,
    _run_tcp_check_multi,
    _run_udp_check,
    _save_pass_strategy_data_block,
)
from blockchecks.engine.nfqws_config import (
    _add_blobs_from_strategy,
    _build_inline_nfqws_lines,
    _build_quic_nfqws_lines,
    _split_cli_args,
    _sudo,
)
from blockchecks.engine.results import (
    PairResult,
    ScanReport,
    TcpTestResult,
    UdpTestResult,
    tcp_results_from_details,
)

__all__ = [
    "AsyncTestRunner",
    "PairResult",
    "ScanReport",
    "StrategyItem",
    "TcpTestResult",
    "UdpTestResult",
    "tcp_results_from_details",
    "_run_tcp_check",
    "_run_tcp_check_multi",
    "_run_quic_check",
    "_run_udp_check",
    "_save_pass_strategy_data_block",
    "_is_quic_dropped",
    "_quic_fallback_variants",
    "_add_blobs_from_strategy",
    "_build_inline_nfqws_lines",
    "_build_quic_nfqws_lines",
    "_split_cli_args",
    "_sudo",
    "_nfqws2_daemon",
    "RETRY_IP_TIMEOUT",
    "BLOB_DIR",
]

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
    ):
        from blockchecks.engine.config import NETNS_BASE

        self.pool = NetNsPool(
            size=pool_size,
            base=f"{NETNS_BASE}-{os.getpid() % 10000:04d}",
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
        self.lua_bridge = lua_bridge
        self.bridge_batch = max(1, bridge_batch)
        self.lua_bridge_compare = lua_bridge_compare
        self.lua_extra = list(lua_extra or [])
        self._probe_gen = 0
        self._batch_id = 0
        self.memory_monitor = None

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
    ) -> list[TcpTestResult]:
        if not items:
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
            result = await self._probe_service(backend).run_batch(ctx, timeout)
        return list(result.results)

    def _next_probe_gen(self) -> int:
        self._probe_gen += 1
        return self._probe_gen

    def _timing_for(self, item: StrategyItem, timeout: float) -> tuple[float, float | None]:
        """Return (curl_timeout, settle_max override) from B11 profile if set."""
        settle_max: float | None = None
        if self.settle_profile:
            override = self.settle_profile.lookup(item.strategy)
            if override:
                settle_max = override.settle_max
                timeout = override.curl_timeout
        return timeout, settle_max

    async def start(self):
        """Create netns pool, seed the Queue, and auto-pin working IPs."""
        await asyncio.to_thread(self.pool.create_all)
        await self.pool.seed()
        if self.auto_pin and self.dns_cache:
            await self._auto_pin_ips()

    async def _auto_pin_ips(self) -> None:
        """Probe DoH/pinned IPs with the known-good fake strategy; pin first PASS.

        The provider hosts file (or ``--fixed-ip`` file) is loaded, its pinned
        domains probed, and only *changed* IPs are written back — so the file
        stays clean in git unless a pinned address actually started failing.
        """
        from blockchecks.checkers.ip_pin import load_pins, merge_pins, save_pins

        file_pins = load_pins(self.pinned_path) if self.pinned_path else {}
        pins = dict(self.dns_cache.pins())
        pins = merge_pins(file_pins, pins)
        self.dns_cache.set_pins(pins)

        domains = [d for d in self.dns_cache.domains() if d]
        if not domains:
            return

        updates: dict[str, str] = {}
        for domain in domains:
            ips = self.dns_cache.candidates(domain)
            if not ips:
                continue
            existing = pins.get(domain)
            candidates = []
            if existing:
                candidates.append(existing)
            for ip in ips:
                if ip not in candidates:
                    candidates.append(ip)
            picked = None
            for ip in candidates:
                if await self._probe_pin_ip(domain, ip):
                    picked = ip
                    break
            if picked:
                updates[domain] = picked
                if self.dns_cache.pinned_ip(domain) != picked:
                    self.dns_cache.add_pin(domain, picked)
                tag = "file" if existing == picked else "auto"
                print(
                    f"  {Fore.CYAN}[dns] pinned {domain} -> {picked} ({tag}){RESET}"
                )
            elif existing:
                # No candidate passed — keep the old pin as a best-effort target
                # rather than dropping it (a stale pin still beats a DoH rotate
                # onto a throttled IP).
                self.dns_cache.add_pin(domain, existing)
                print(
                    f"  {Fore.YELLOW}[dns] pin kept for {domain} -> {existing} "
                    f"(no working fallback){RESET}"
                )

        if self.pinned_path:
            merged = merge_pins(file_pins, updates)
            if merged != file_pins:
                try:
                    save_pins(self.pinned_path, merged)
                    print(f"  {Fore.CYAN}[dns] saved pinned IPs -> {self.pinned_path}{RESET}")
                except OSError as e:
                    print(f"  {Fore.YELLOW}[dns] cannot save pins {self.pinned_path}: {e}{RESET}")
            else:
                print(f"  {Fore.CYAN}[dns] pins unchanged -> {self.pinned_path}{RESET}")

    async def _probe_pin_ip(self, domain: str, ip: str) -> bool:
        """Return True when ``fake:blob=stun`` passes to *domain* via *ip*."""
        ns = await self.pool.acquire()
        try:
            data = await asyncio.to_thread(
                _run_tcp_check,
                ns,
                PIN_STRATEGY,
                domain,
                PIN_TIMEOUT,
                False,
                self.python,
                self.disable_ech,
                ip,
                1,
                False,
                "",
                "tls12",
                PIN_SETTLE_MAX,
                None,
                "fast",
                False,
            )
            return bool(data.get("success"))
        finally:
            await self.pool.release(ns)

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
                proto_db = "http" if protocol == "http" else "tcp"
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
                if (
                    not data.get("success")
                    and self.try_wssize
                    and protocol == "tls12"
                    and "wssize" not in item.strategy
                ):
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
                        "wssize:wsize=1:scale=6",
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
                result.error = data.get("error", "") or ""

                if self.db:
                    if result.throttled:
                        status = "THROTTLED"
                    elif result.success:
                        status = "PASS"
                    else:
                        status = "FAIL"
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
                        resolved_ip=resolved_ip or "",
                        dns_verdict=dns_verdict,
                        doh_server=doh_server,
                        proto=proto_db,
                    )
            except Exception as e:
                result.error = str(e)[:200]
            finally:
                await self.pool.release(ns_name)

        return result

    async def test_quic(
        self, item: StrategyItem, domain: str, timeout: float = 8.0
    ) -> TcpTestResult:
        """Test one QUIC/HTTP3 strategy in an isolated netns (BC2-10)."""
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
                    if result.success or not _is_quic_dropped(result.error):
                        break
                    # timeout = TSPU dropped this variant; try the next fallback.
                    if variant != variants[-1]:
                        print(
                            f"  {YELLOW}[quic] {item.label[:24]} timeout "
                            f"— trying fallback: {variant[:40]}...{RESET}"
                        )

                if self.db:
                    status = "PASS" if result.success else "FAIL"
                    await self.db.log_tcp(
                        item.label,
                        domain,
                        status,
                        result.latency_ms,
                        result.http_code,
                        content_valid=True,
                        error=result.error,
                        config_path=item.strategy,
                        resolved_ip=resolved_ip or "",
                        dns_verdict=dns_verdict,
                        doh_server=doh_server,
                        proto="quic",
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
            except Exception:
                pass
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
        if "bridge_applied" in data and data.get("bridge_applied") is False and result.success:
            print(
                f"  {YELLOW}WARN: bridge PASS without APPLIED event for "
                f"{item.label[:24]} (strategy may not have been picked up by nfqws2){RESET}"
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
        if not self.db:
            return
        protocol = getattr(item, "protocol", "tls12") or "tls12"
        proto_db = "http" if protocol == "http" else "tcp"
        if result.throttled:
            status = "THROTTLED"
        elif result.success:
            status = "PASS"
        else:
            status = "FAIL"
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
            resolved_ip=(result.used_ip or resolved_ip or ""),
            dns_verdict=dns_verdict,
            doh_server=doh_server,
            proto=proto_db,
        )
        if status == "PASS":
            await _save_pass_strategy_data_block(
                item.strategy,
                domain,
                protocol=proto_db,
                latency_ms=result.latency_ms,
                http_code=result.http_code,
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
                    if (
                        not data.get("success")
                        and self.try_wssize
                        and protocol == "tls12"
                        and "wssize" not in item.strategy
                    ):
                        data = await asyncio.to_thread(
                            _run_tcp_check,
                            ns_name,
                            item.strategy,
                            domain,
                            timeout,
                            item.is_config,
                            self.python,
                            self.disable_ech,
                            resolved_ips.get(domain),
                            self.repeats,
                            self.parallel_repeats,
                            "wssize:wsize=1:scale=6",
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

                if self.db:
                    await self.db.log_udp(
                        item.label,
                        target,
                        "PASS" if result.success else "FAIL",
                        result.latency_ms,
                        result.error,
                        config_path=item.strategy,
                    )
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
                    print(
                        f"  {RED}BRIDGE_COMPARE drift: {c.item.label[:24]} "
                        f"classic={c.success}/{c.http_code} bridge={b.success}/{b.http_code}{RESET}"
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
            if r.throttled:
                tag = f"{YELLOW}THROTTLED{RESET}"
            elif r.success:
                tag = f"{GREEN}OK{RESET}"
            else:
                tag = f"{RED}FAIL{RESET}"
            lat = f"{r.latency_ms:.0f}ms" if r.latency_ms else ""
            status = f"HTTP {r.http_code}" if r.http_code else ""
            err = f" — {r.error[:40]}" if r.error else ""
            label = r.item.label[:30]
            print(f"  [{tag}] {lat:>6s}  {status:>8s}  {label}{err}")

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
            print(f"\n  {RED}No PASS TCP — UDP skipped{RESET}")
            return pairs

        total = len(working) * len(udp_strategies)

        # Resume: skip only pairs already in DB (completed-set).
        # Checkpoint idx is NOT used for skip — parallel pairs make idx a non-frontier.
        completed: set[tuple[str, str]] = set()
        if self.db:
            try:
                completed = await self.db.get_completed_pair_keys(log_domain)
            except Exception:
                completed = set()
        if isinstance(resume_from, Checkpoint) and resume_from.tcp_label:
            print(
                f"  {YELLOW}Resuming after "
                f"{resume_from.tcp_label}+{resume_from.udp_label} "
                f"({len(completed)} pairs in DB){RESET}"
            )
        elif resume_from is not None and getattr(resume_from, "tcp_label", None):
            print(
                f"  {YELLOW}Resuming after "
                f"{resume_from.tcp_label}+{getattr(resume_from, 'udp_label', '')} "
                f"({len(completed)} pairs in DB){RESET}"
            )
        elif completed:
            print(f"  {YELLOW}Resuming: {len(completed)} pairs already in DB{RESET}")
        ep_tag = f" ep={voice_ip}:{voice_port}" if pair_domain else ""
        print(
            f"  {CYAN}Pair matrix: {len(working)} TCP × {len(udp_strategies)} UDP "
            f"= {total} pairs, {self.pool.size} parallel{ep_tag}{RESET}"
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
                    print(
                        f"  [{pair_tag}] {tcp_r.item.label[:22]:22s} "
                        f"+ {udp_s.label[:22]:22s}  udp={udp_tag}{voice_tag}"
                    )

                    if self.db:
                        async with db_lock:
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

        await asyncio.gather(*tasks, return_exceptions=True)
        return pairs

    # ── Matrix display ──

    @staticmethod
    def print_matrix(pairs: list[PairResult]):
        """Print colored pair matrix to console."""
        if not pairs:
            return
        tcp_names = sorted(set(p.tcp_item.label for p in pairs))
        udp_names = sorted(set(p.udp_item.label for p in pairs))
        pair_map = {f"{p.tcp_item.label}|{p.udp_item.label}": p for p in pairs}

        print(f"\n  {CYAN}╔{'═' * 60}╗{RESET}")
        print(f"  {CYAN}║{'TCP×UDP Pair Matrix':^60s}║{RESET}")

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
                print(f"  {tag:12s} {tcp[:22]:22s} + {udp[:22]:22s}  udp={udp_lat}")

        print(f"  {CYAN}{'═' * 60}{RESET}")
        print(f"  {GREEN}{passed} PASS{RESET} / {len(pairs)} pairs")
