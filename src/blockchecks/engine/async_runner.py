"""Async parallel test runner — builds on NetNsPool for concurrent DPI tests.

Each test runs in its own pre-created netns from the pool.
curl_cffi is called via asyncio.to_thread() (libcurl is C, not async).
"""

import asyncio
import json
import os
import subprocess as sp
from dataclasses import dataclass, field

from colorama import Fore, Style
from colorama import init as colorama_init

colorama_init(autoreset=True)

from blockchecks.checkers.curl_probe import (
    CurlProbeRequest,
    is_googlevideo_domain,
    prepare_googlevideo_probe,
    worker_wall_timeout,
)
from blockchecks.checkers.dns_secure import DnsRunCache
from blockchecks.engine.config import (
    BLOB_DIR,
    NFQUEUE_TCP,
    NFQUEUE_UDP,
    PYTHON_BIN,
    get_lua_init_scripts,
    get_nfqws2_bin,
)
from blockchecks.engine.matrix_generator import StrategyItem
from blockchecks.engine.netns_pool import NetNsPool
from blockchecks.engine.probe import (
    invoke_curl_probe_worker as _invoke_curl_probe_worker,
)
from blockchecks.engine.probe import probe_request_dict as _probe_request_dict
from blockchecks.engine.settle_profile import SettleProfile
from blockchecks.engine.store import RunStateStore

GREEN = Fore.GREEN + Style.BRIGHT
RED = Fore.RED + Style.BRIGHT
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
GREY = Fore.LIGHTBLACK_EX
RESET = Style.RESET_ALL

__all__ = [
    "AsyncTestRunner",
    "PairResult",
    "StrategyItem",
    "TcpTestResult",
    "UdpTestResult",
    "tcp_results_from_details",
]


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
    tcp_results: list[TcpTestResult] = field(default_factory=list)
    pairs: list[PairResult] = field(default_factory=list)
    total_time_sec: float = 0
    voice_info: dict = field(default_factory=dict)


# ── Utility: run command synchronously (called via asyncio.to_thread) ──


from blockchecks.engine.nfqws2 import start_daemon as _nfqws2_daemon


def _sudo(*args: str) -> str:
    r = sp.run(["sudo"] + list(args), capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        raise RuntimeError(f"sudo {' '.join(args)}: {r.stderr[:200]}")
    return r.stdout.strip()


def _add_blobs_from_strategy(lines: list[str], strategy: str) -> None:
    """Parse strategy for blob=NAME and seqovl_pattern=NAME; add --blob lines."""
    import re

    from blockchecks.engine.blob_aliases import resolve_blob_path

    def _append_blob(name: str) -> None:
        if name == "0x00000000":
            return
        if any(line.startswith(f"--blob={name}:@") for line in lines):
            return
        path = resolve_blob_path(name, BLOB_DIR)
        if path:
            lines.append(f"--blob={name}:@{path}")

    for m in re.finditer(r"(?:blob|pattern|seqovl_pattern)=(\w+)", strategy):
        _append_blob(m.group(1))


def _split_cli_args(raw_line: str) -> list[str]:
    """Split a line of nfqws2 CLI args on ' --' boundaries."""
    out = []
    for arg in raw_line.split(" --"):
        arg = arg.strip()
        if not arg:
            continue
        if not arg.startswith("--"):
            arg = "--" + arg
        out.append(arg)
    return out


# ── In-namespace test workers (sync, called via asyncio.to_thread) ──


def _build_inline_nfqws_lines(
    strategy: str, protocol: str, extra_lua_desync: str = ""
) -> list[str]:
    """Build nfqws2 config lines for inline lua-desync strategy."""
    is_http = protocol == "http"
    if is_http:
        config_lines = [
            f"--qnum={NFQUEUE_TCP}",
            "--filter-tcp=80",
            "--filter-l3=ipv4",
            "--filter-l7=http",
            "--ipcache-lifetime=0",
            "--bind-fix4",
            "--payload=http_req",
        ]
    else:
        config_lines = [
            f"--qnum={NFQUEUE_TCP}",
            "--filter-tcp=443",
            "--filter-l3=ipv4",
            "--filter-l7=tls",
            "--ipcache-lifetime=0",
            "--bind-fix4",
            "--payload=tls_client_hello",
        ]
    for lua in get_lua_init_scripts():
        if os.path.exists(lua):
            config_lines.append(f"--lua-init=@{lua}")
    _add_blobs_from_strategy(config_lines, strategy)
    for raw_line in strategy.split("\n"):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        if raw_line.startswith("--"):
            config_lines.extend(_split_cli_args(raw_line))
        else:
            config_lines.append(f"--lua-desync={raw_line}")
    if extra_lua_desync:
        config_lines.append(f"--lua-desync={extra_lua_desync}")
    return config_lines


def _build_quic_nfqws_lines(strategy: str) -> list[str]:
    """Build nfqws2 config for HTTP/3 QUIC strategies (UDP/443, BC2-10)."""
    if strategy.strip().startswith("--"):
        config_lines = [
            f"--qnum={NFQUEUE_UDP}",
            "--filter-l3=ipv4",
            "--ipcache-lifetime=0",
            "--bind-fix4",
        ]
        for lua in get_lua_init_scripts():
            if os.path.exists(lua):
                config_lines.append(f"--lua-init=@{lua}")
        for raw_line in strategy.split("\n"):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            config_lines.extend(_split_cli_args(raw_line))
        return config_lines

    config_lines = [
        f"--qnum={NFQUEUE_UDP}",
        "--filter-udp=443",
        "--filter-l3=ipv4",
        "--filter-l7=quic",
        "--ipcache-lifetime=0",
        "--bind-fix4",
        "--payload=quic_initial",
    ]
    for lua in get_lua_init_scripts():
        if os.path.exists(lua):
            config_lines.append(f"--lua-init=@{lua}")
    _add_blobs_from_strategy(config_lines, strategy)
    for raw_line in strategy.split("\n"):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        if raw_line.startswith("--"):
            config_lines.extend(_split_cli_args(raw_line))
        else:
            config_lines.append(f"--lua-desync={raw_line}")
    return config_lines


def _run_quic_check(
    ns_name: str,
    strategy: str,
    domain: str,
    timeout: float,
    is_config: bool = False,
    python_bin: str = None,
    resolved_ip: str | None = None,
) -> dict:
    """Start nfqws2 QUIC desync in ns, probe domain via HTTP/3 HEAD."""
    py = python_bin or PYTHON_BIN
    tmp_conf = None

    if is_config:
        import shutil
        import tempfile as _tf

        src = os.path.abspath(strategy) if not os.path.isabs(strategy) else strategy
        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_quic_", suffix=".conf")
        os.close(_tf_fd)
        shutil.copy2(src, tmp_conf)
        _nfqws2_daemon(ns_name, tmp_conf)
    else:
        import tempfile as _tf

        config_lines = _build_quic_nfqws_lines(strategy)
        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_quic_", suffix=".conf")
        os.close(_tf_fd)
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        _nfqws2_daemon(ns_name, tmp_conf)

    _sudo(
        "ip",
        "netns",
        "exec",
        ns_name,
        "iptables",
        "-A",
        "OUTPUT",
        "-p",
        "udp",
        "--dport",
        "443",
        "-j",
        "NFQUEUE",
        "--queue-num",
        str(NFQUEUE_UDP),
        "--queue-bypass",
    )

    resolved_ip_lit = repr(resolved_ip) if resolved_ip else "None"
    check_code = f"""
import json
from blockchecks.checkers.http3 import check_http3
r = check_http3({domain!r}, {timeout}, pre_resolved_ip={resolved_ip_lit})
print(json.dumps({{
    "success": r.success,
    "http_code": r.http_status,
    "latency_ms": r.latency_ms,
    "content_len": r.content_length,
    "content_ok": True,
    "throttled": False,
    "read_rate_bps": 0,
    "error": r.error,
    "http_version": r.http_version,
}}))
"""
    try:
        r = sp.run(
            ["sudo", "ip", "netns", "exec", ns_name, py, "-c", check_code],
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            return {
                "success": False,
                "http_code": 0,
                "latency_ms": 0,
                "content_len": 0,
                "content_ok": False,
                "throttled": False,
                "read_rate_bps": 0,
                "error": f"parse: {r.stdout[:100]}",
            }
    finally:
        if tmp_conf:
            try:
                os.unlink(tmp_conf)
            except OSError:
                pass


def _run_tcp_check(
    ns_name: str,
    strategy: str,
    domain: str,
    timeout: float,
    is_config: bool = False,
    python_bin: str = None,
    disable_ech: bool = False,
    resolved_ip: str | None = None,
    repeats: int = 1,
    parallel_repeats: bool = False,
    extra_lua_desync: str = "",
    protocol: str = "tls12",
    settle_max: float | None = None,
    settle_poll: float | None = None,
    repeats_mode: str = "fast",
    quick_break: bool = False,
) -> dict:
    """Start nfqws2 in ns, run curl_cffi check, return result dict."""

    py = python_bin or PYTHON_BIN
    is_http = protocol == "http"
    is_gv = not is_http and is_googlevideo_domain(domain)
    dport = "80" if is_http else "443"
    tmp_conf = None

    if is_gv:
        probe_req, gv_err = prepare_googlevideo_probe(domain, resolved_ip=resolved_ip)
        if gv_err:
            return gv_err
        resolved_ip = probe_req.resolved_ip
    else:
        probe_req = CurlProbeRequest(
            domain=domain,
            timeout=timeout,
            resolved_ip=resolved_ip,
            resolve_name=domain.split("/")[0],
            disable_ech=disable_ech,
            protocol=protocol,
        )
    if is_config:
        src = os.path.abspath(strategy) if not os.path.isabs(strategy) else strategy
        # Copy user conf — inject daemon/debug without mutating the original
        import shutil
        import tempfile as _tf

        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_", suffix=".conf")
        os.close(_tf_fd)
        shutil.copy2(src, tmp_conf)
        if extra_lua_desync:
            with open(tmp_conf, "a", encoding="utf-8") as f:
                f.write(f"\n--lua-desync={extra_lua_desync}\n")
        settle_elapsed = _nfqws2_daemon(
            ns_name, tmp_conf, settle_max=settle_max, settle_poll=settle_poll
        )
    else:
        config_lines = _build_inline_nfqws_lines(strategy, protocol, extra_lua_desync)
        import tempfile as _tf

        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_", suffix=".conf")
        os.close(_tf_fd)
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        settle_elapsed = _nfqws2_daemon(
            ns_name, tmp_conf, settle_max=settle_max, settle_poll=settle_poll
        )

    _sudo(
        "ip",
        "netns",
        "exec",
        ns_name,
        "iptables",
        "-A",
        "OUTPUT",
        "-p",
        "tcp",
        "--dport",
        dport,
        "-j",
        "NFQUEUE",
        "--queue-num",
        str(NFQUEUE_TCP),
        "--queue-bypass",
    )

    probe_req.timeout = timeout
    payload = {
        "mode": "single",
        "request": _probe_request_dict(probe_req),
        "repeats": max(1, int(repeats)),
        "parallel_repeats": bool(parallel_repeats and repeats > 1),
        "repeats_mode": repeats_mode,
        "quick_break": bool(quick_break),
    }
    try:
        wall = worker_wall_timeout(
            timeout,
            repeats,
            n_domains=1,
            curl_parallel=1,
            parallel_repeats=parallel_repeats,
        )
        data = _invoke_curl_probe_worker(ns_name, py, payload, wall)
        data["settle_ms"] = round(settle_elapsed * 1000, 1)
        return data
    finally:
        if tmp_conf:
            try:
                os.unlink(tmp_conf)
            except OSError:
                pass


def _run_tcp_check_multi(
    ns_name: str,
    strategy: str,
    domains: list[str],
    timeout: float,
    *,
    is_config: bool = False,
    python_bin: str | None = None,
    disable_ech: bool = False,
    resolved_ips: dict[str, str | None] | None = None,
    repeats: int = 1,
    extra_lua_desync: str = "",
    protocol: str = "tls12",
    curl_parallel: int = 4,
    settle_max: float | None = None,
    settle_poll: float | None = None,
    parallel_repeats: bool = False,
    repeats_mode: str = "fast",
    quick_break: bool = False,
) -> dict[str, dict]:
    """One nfqws2 session, parallel curl across domains (B2)."""
    if not domains:
        return {}
    py = python_bin or PYTHON_BIN
    is_http = protocol == "http"
    dport = "80" if is_http else "443"
    tmp_conf = None
    resolved_ips = dict(resolved_ips or {})
    gv_fail: dict[str, dict] = {}
    probe_requests: list[CurlProbeRequest] = []

    for d in domains:
        if not is_http and is_googlevideo_domain(d):
            req, err = prepare_googlevideo_probe(d, resolved_ip=resolved_ips.get(d))
            if err:
                gv_fail[d] = err
                continue
            if req.resolved_ip:
                resolved_ips[d] = req.resolved_ip
            probe_requests.append(req)
        else:
            probe_requests.append(
                CurlProbeRequest(
                    domain=d,
                    timeout=timeout,
                    resolved_ip=resolved_ips.get(d),
                    resolve_name=d.split("/")[0],
                    disable_ech=disable_ech,
                    protocol=protocol,
                )
            )

    domains_active = [r.domain for r in probe_requests]
    if not domains_active:
        return gv_fail

    if is_config:
        import shutil
        import tempfile as _tf

        src = os.path.abspath(strategy) if not os.path.isabs(strategy) else strategy
        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_multi_", suffix=".conf")
        os.close(_tf_fd)
        shutil.copy2(src, tmp_conf)
        if extra_lua_desync:
            with open(tmp_conf, "a", encoding="utf-8") as f:
                f.write(f"\n--lua-desync={extra_lua_desync}\n")
        settle_elapsed = _nfqws2_daemon(
            ns_name, tmp_conf, settle_max=settle_max, settle_poll=settle_poll
        )
    else:
        import tempfile as _tf

        config_lines = _build_inline_nfqws_lines(strategy, protocol, extra_lua_desync)
        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_multi_", suffix=".conf")
        os.close(_tf_fd)
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        settle_elapsed = _nfqws2_daemon(
            ns_name, tmp_conf, settle_max=settle_max, settle_poll=settle_poll
        )

    _sudo(
        "ip",
        "netns",
        "exec",
        ns_name,
        "iptables",
        "-A",
        "OUTPUT",
        "-p",
        "tcp",
        "--dport",
        dport,
        "-j",
        "NFQUEUE",
        "--queue-num",
        str(NFQUEUE_TCP),
        "--queue-bypass",
    )

    for req in probe_requests:
        req.timeout = timeout

    payload = {
        "mode": "batch",
        "requests": [_probe_request_dict(r) for r in probe_requests],
        "curl_parallel": int(curl_parallel),
        "repeats": max(1, int(repeats)),
        "parallel_repeats": bool(parallel_repeats and repeats > 1),
        "repeats_mode": repeats_mode,
        "quick_break": bool(quick_break),
    }
    try:
        wall = worker_wall_timeout(
            timeout,
            repeats,
            n_domains=len(domains_active),
            curl_parallel=int(curl_parallel),
            parallel_repeats=parallel_repeats,
        )
        raw = _invoke_curl_probe_worker(ns_name, py, payload, wall)
        settle_ms = round(settle_elapsed * 1000, 1)
        out = {
            d: {**raw.get(d, {}), "settle_ms": settle_ms}
            for d in domains_active
        }
        out.update(gv_fail)
        return out
    finally:
        if tmp_conf:
            try:
                os.unlink(tmp_conf)
            except OSError:
                pass


def _run_udp_check(
    ns_name: str,
    strategy: str,
    ip: str,
    port: int,
    timeout: float,
    is_config: bool = False,
    python_bin: str = None,
    coexist: bool = False,
) -> dict:
    """Start nfqws2 UDP in ns, run STUN probe, return result.

    coexist=True: do not pkill existing nfqws2 (keep TCP desync for pairs).
    """

    py = python_bin or PYTHON_BIN
    kill_existing = not coexist
    tmp_conf = None

    if is_config:
        src = os.path.abspath(strategy) if not os.path.isabs(strategy) else strategy
        import shutil
        import tempfile as _tf2

        _tf2_fd, tmp_conf = _tf2.mkstemp(prefix="bs_async_udp_", suffix=".conf")
        os.close(_tf2_fd)
        shutil.copy2(src, tmp_conf)
        _nfqws2_daemon(ns_name, tmp_conf, kill_existing=kill_existing)
    elif strategy.strip().startswith("--"):
        # Full CLI config (standard_udp dual-blob etc.)
        config_lines = [
            f"--qnum={NFQUEUE_UDP}",
            "--filter-l3=ipv4",
            "--ipcache-lifetime=0",
            "--bind-fix4",
        ]
        for lua in get_lua_init_scripts():
            if os.path.exists(lua):
                config_lines.append(f"--lua-init=@{lua}")
        for raw_line in strategy.split("\n"):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            config_lines.extend(_split_cli_args(raw_line))
        import tempfile as _tf2

        _tf2_fd, tmp_conf = _tf2.mkstemp(prefix="bs_async_udp_", suffix=".conf")
        os.close(_tf2_fd)
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        _nfqws2_daemon(ns_name, tmp_conf, kill_existing=kill_existing)
    else:
        # Inline lua-desync core (e.g. fake:blob=discord_udp:repeats=6)
        config_lines = [
            f"--qnum={NFQUEUE_UDP}",
            "--filter-udp=50000-50100",
            "--filter-l3=ipv4",
            "--ipcache-lifetime=0",
            "--bind-fix4",
        ]
        for lua in get_lua_init_scripts():
            if os.path.exists(lua):
                config_lines.append(f"--lua-init=@{lua}")
        _add_blobs_from_strategy(config_lines, strategy)
        if not any(line.startswith("--blob=") for line in config_lines):
            blob = os.path.join(BLOB_DIR, "discord_udp.bin")
            if os.path.exists(blob):
                config_lines.append(f"--blob=discord_udp:@{blob}")
        config_lines.append(f"--lua-desync={strategy}")
        import tempfile as _tf2

        _tf2_fd, tmp_conf = _tf2.mkstemp(prefix="bs_async_udp_", suffix=".conf")
        os.close(_tf2_fd)
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        _nfqws2_daemon(ns_name, tmp_conf, kill_existing=kill_existing)

    _sudo(
        "ip",
        "netns",
        "exec",
        ns_name,
        "iptables",
        "-A",
        "OUTPUT",
        "-p",
        "udp",
        "--dport",
        str(port),
        "-j",
        "NFQUEUE",
        "--queue-num",
        str(NFQUEUE_UDP),
        "--queue-bypass",
    )

    probe_code = f"""
import json
from blockchecks.checkers.udp_voice import voice_udp_probe
ok, lat, detail, method = voice_udp_probe({ip!r}, {port}, {timeout})
print(json.dumps({{"success": ok, "latency_ms": lat,
    "detail": detail, "method": method}}))
"""
    try:
        r = sp.run(
            ["sudo", "ip", "netns", "exec", ns_name, py, "-c", probe_code],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            return {"success": False, "latency_ms": 0, "detail": "parse error"}
    finally:
        if tmp_conf:
            try:
                os.unlink(tmp_conf)
            except OSError:
                pass


# ── AsyncTestRunner ─────────────────────────────────


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
        repeats: int = 1,
        parallel_repeats: bool = False,
        repeats_mode: str = "fast",
        quick_break: bool = False,
        try_wssize: bool = False,
        settle_profile: SettleProfile | None = None,
    ):
        self.pool = NetNsPool(size=pool_size)
        self.semaphore = asyncio.Semaphore(pool_size)
        self.db = db
        self.python = python_path or PYTHON_BIN
        self.matrix_fingerprint: str = ""
        self.disable_ech = disable_ech
        self.secure_dns = secure_dns
        self.dns_cache = dns_cache
        self.dns_audit = dns_audit or {}
        from blockchecks.checkers.curl_probe import clamp_repeats

        self.repeats = clamp_repeats(repeats)
        self.parallel_repeats = parallel_repeats
        self.repeats_mode = repeats_mode or "fast"
        self.quick_break = quick_break
        self.try_wssize = try_wssize
        self.settle_profile = settle_profile

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
        """Create netns pool and seed the asyncio Queue on the event loop."""
        await asyncio.to_thread(self.pool.create_all)
        await self.pool.seed()

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
                    )
                result.success = data.get("success", False)
                result.http_code = data.get("http_code", 0)
                result.latency_ms = data.get("latency_ms", 0)
                result.content_length = data.get("content_len", 0)
                result.content_valid = data.get("content_ok", True)
                result.throttled = data.get("throttled", False)
                result.read_rate_bps = data.get("read_rate_bps", 0)
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
                data = await asyncio.to_thread(
                    _run_quic_check,
                    ns_name,
                    item.strategy,
                    domain,
                    timeout,
                    item.is_config,
                    self.python,
                    resolved_ip,
                )
                result.success = data.get("success", False)
                result.http_code = data.get("http_code", 0)
                result.latency_ms = data.get("latency_ms", 0)
                result.content_length = data.get("content_len", 0)
                result.error = data.get("error", "") or ""

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

    def _tcp_result_from_data(
        self, item: StrategyItem, domain: str, data: dict
    ) -> TcpTestResult:
        result = TcpTestResult(item=item, domain=domain)
        result.success = data.get("success", False)
        result.http_code = data.get("http_code", 0)
        result.latency_ms = data.get("latency_ms", 0)
        result.content_length = data.get("content_len", 0)
        result.content_valid = data.get("content_ok", True)
        result.throttled = data.get("throttled", False)
        result.read_rate_bps = data.get("read_rate_bps", 0)
        result.error = data.get("error", "") or ""
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
            resolved_ip=resolved_ip or "",
            dns_verdict=dns_verdict,
            doh_server=doh_server,
            proto=proto_db,
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
                dns_meta: dict[str, tuple[str, str]] = {}
                for domain in domains:
                    rip, dv, ds = await self._resolve_domain_dns(domain)
                    resolved_ips[domain] = rip
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
        """Parallel batch of TCP strategy tests."""
        if not strategies:
            return []

        tasks = []
        for s in strategies:
            task = asyncio.create_task(self.test_tcp(s, domain, timeout))
            tasks.append(task)

        results = []
        for task in asyncio.as_completed(tasks):
            r = await task
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
            results.append(r)

        return list(results)  # maintain order via tasks list

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
    ) -> list[PairResult]:
        """Parallel UDP probes for each PASS TCP × each UDP strategy.

        Each pair runs in its own netns via asyncio.create_task + Semaphore.
        TCP nfqws2 started once per pair, UDP nfqws2 per strategy.
        DB writes serialized via asyncio.Lock.
        """
        from blockchecks.engine.store.models import Checkpoint

        pairs: list[PairResult] = []
        db_lock = asyncio.Lock()
        pair_sem = asyncio.Semaphore(self.pool.size)
        fp = fingerprint or self.matrix_fingerprint

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
                completed = await self.db.get_completed_pair_keys(domain)
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
        print(
            f"  {CYAN}Pair matrix: {len(working)} TCP × {len(udp_strategies)} UDP "
            f"= {total} pairs, {self.pool.size} parallel{RESET}"
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
                                domain,
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
                                f"{tcp_r.item.label}+{udp_s.label}",
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
