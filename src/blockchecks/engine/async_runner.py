"""Async parallel test runner — builds on NetNsPool for concurrent DPI tests.

Each test runs in its own pre-created netns from the pool.
curl_cffi is called via asyncio.to_thread() (libcurl is C, not async).
"""

import asyncio
import json
import os
import subprocess as sp
import time
from dataclasses import dataclass, field

from colorama import Fore, Style
from colorama import init as colorama_init

colorama_init(autoreset=True)

from blockchecks.checkers.dns_secure import CURLOPT_RESOLVE, DnsRunCache
from blockchecks.engine.config import (
    BLOB_DIR,
    CURLOPT_ECH,
    GOOGLEVIDEO_RANGE_SIZE,
    MIN_READ_RATE_BPS,
    NFQWS2_BIN,
    PYTHON_BIN,
    THROTTLED_MAX_BPS,
    nfqws2_debug_conf_line,
)
from blockchecks.engine.db_logger import StateDB
from blockchecks.engine.matrix_generator import StrategyItem
from blockchecks.engine.netns_pool import NetNsPool

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


def _sudo(*args: str) -> str:
    r = sp.run(["sudo"] + list(args), capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        raise RuntimeError(f"sudo {' '.join(args)}: {r.stderr[:200]}")
    return r.stdout.strip()


def _nfqws2_daemon(ns_name: str, config_path: str, kill_existing: bool = True) -> None:
    """Launch nfqws2 in daemon mode inside ns. Non-blocking.

    kill_existing=True (default) clears prior nfqws2 in the ns — for solo
    TCP/UDP checks. Pair matrix must pass kill_existing=False when starting
    the UDP instance so the TCP desync (qnum 200) stays alive.

    Note: with ``@config`` nfqws2 ignores trailing CLI flags — put ``--debug``
    and ``--daemon`` inside the config file (see ``_inject_debug_and_daemon``).
    """
    _inject_debug_and_daemon(config_path, tag=ns_name)
    if kill_existing:
        sp.run(
            ["sudo", "ip", "netns", "exec", ns_name, "pkill", "-9", "nfqws2"],
            stdout=sp.DEVNULL,
            stderr=sp.DEVNULL,
        )
    # @config must be the only argument; daemon/debug are inside the file
    cmd = ["sudo", "ip", "netns", "exec", ns_name, NFQWS2_BIN, f"@{config_path}"]
    sp.Popen(cmd, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
    time.sleep(2.0)


def _inject_debug_and_daemon(config_path: str, tag: str = "") -> str | None:
    """Ensure conf contains --daemon and optional --debug=@log. Returns log path."""
    try:
        with open(config_path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return None
    lines = [ln for ln in text.splitlines() if ln.strip()]
    changed = False
    if not any(ln.startswith("--daemon") for ln in lines):
        lines.insert(0, "--daemon")
        changed = True
    dbg, dbg_path = nfqws2_debug_conf_line(tag=tag or "async")
    if dbg and not any(ln.startswith("--debug=") for ln in lines):
        lines.insert(1 if lines and lines[0].startswith("--daemon") else 0, dbg)
        changed = True
        if dbg_path:
            print(f"  [nfqws2 debug] {dbg_path}")
    if changed:
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except OSError:
            return None
    return dbg_path if dbg else None


def _add_blobs_from_strategy(lines: list[str], strategy: str) -> None:
    """Parse strategy for blob=NAME and seqovl_pattern=NAME; add --blob lines."""
    import re

    if not os.path.isdir(BLOB_DIR):
        return
    known = sorted(f for f in os.listdir(BLOB_DIR) if f.endswith(".bin"))

    def _append_blob(name: str) -> None:
        if name == "0x00000000":
            return
        if any(line.startswith(f"--blob={name}:@") for line in lines):
            return
        candidates = [f for f in known if name in f and "quic_initial" not in f]
        if not candidates:
            candidates = [f for f in known if name in f]
        if candidates:
            lines.append(f"--blob={name}:@{BLOB_DIR}/{candidates[0]}")

    for m in re.finditer(r"blob=(\w+)", strategy):
        _append_blob(m.group(1))
    for m in re.finditer(r"seqovl_pattern=(\w+)", strategy):
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
            "--qnum=200",
            "--filter-tcp=80",
            "--filter-l3=ipv4",
            "--filter-l7=http",
            "--ipcache-lifetime=0",
            "--bind-fix4",
            "--payload=http_req",
        ]
    else:
        config_lines = [
            "--qnum=200",
            "--filter-tcp=443",
            "--filter-l3=ipv4",
            "--filter-l7=tls",
            "--ipcache-lifetime=0",
            "--bind-fix4",
            "--payload=tls_client_hello",
        ]
    for lua in ["/opt/zapret2/lua/zapret-lib.lua", "/opt/zapret2/lua/zapret-antidpi.lua"]:
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
) -> dict:
    """Start nfqws2 in ns, run curl_cffi check, return result dict."""

    py = python_bin or PYTHON_BIN
    is_http = protocol == "http"
    is_gv = not is_http and "googlevideo" in domain.lower()
    use_ech = not is_http and (disable_ech or is_gv)
    dport = "80" if is_http else "443"
    tmp_conf = None

    # Setup nfqws2
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
        _nfqws2_daemon(ns_name, tmp_conf)
    else:
        config_lines = _build_inline_nfqws_lines(strategy, protocol, extra_lua_desync)
        import tempfile as _tf

        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_", suffix=".conf")
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
        "tcp",
        "--dport",
        dport,
        "-j",
        "NFQUEUE",
        "--queue-num",
        "200",
        "--queue-bypass",
    )

    range_end = GOOGLEVIDEO_RANGE_SIZE - 1
    headers_extra = ""
    if is_gv:
        headers_extra = f', "Range": "bytes=0-{range_end}"'
    use_ech_int = 1 if use_ech else 0
    ech_opt = CURLOPT_ECH
    resolved_ip_lit = repr(resolved_ip)
    repeats = max(1, int(repeats))
    parallel_int = 1 if parallel_repeats and repeats > 1 else 0
    url_scheme = "http" if is_http else "https"
    resolve_port = 80 if is_http else 443

    check_code = f"""
import json, time
def check(domain, timeout, resolved_ip):
    try:
        import curl_cffi
        start = time.perf_counter()
        headers = {{"Accept": "text/html"{headers_extra}}}
        resolve_opt = {CURLOPT_RESOLVE}
        try:
            s = curl_cffi.Session(
                impersonate="chrome124", http_version=2,
                headers=headers, allow_redirects=False,
            )
            if resolved_ip:
                s.curl.setopt(resolve_opt, [domain + ":{resolve_port}:" + resolved_ip])
            if {use_ech_int}:
                set = False
                try:
                    s.curl.setopt(curl_cffi.CurlOpt.ECH, "")
                    set = True
                except Exception:
                    pass
                if not set:
                    try:
                        s.curl.setopt({ech_opt}, "")
                    except Exception as e:
                        return {{"success": False, "http_code": 0,
                                  "latency_ms": (time.perf_counter()-start)*1000,
                                  "content_len": 0, "content_ok": False,
                                  "throttled": False, "read_rate_bps": 0,
                                  "error": "ech_setopt:" + str(e)[:100]}}
            resp = s.get("{url_scheme}://" + domain, timeout=min(timeout, 1.5))
        except curl_cffi.CurlError as e:
            msg = str(e)
            return {{"success": False, "http_code": 0,
                      "latency_ms": (time.perf_counter()-start)*1000,
                      "content_len": 0, "content_ok": False,
                      "throttled": False, "read_rate_bps": 0,
                      "error": "timeout" if "Timeout" in msg else msg[:120]}}
        elapsed = max(time.perf_counter()-start, 0.001)
        body = resp.content[:4096]
        clen = len(resp.content)
        rate = clen / elapsed
        loc = resp.headers.get("Location") or resp.headers.get("location") or ""
        dom = domain.lower().split("/")[0]
        if resp.status_code in (301, 302, 307, 308) and loc:
            if loc.lower().startswith(("http://", "https://")):
                redir_host = loc.split("/")[2].split(":")[0].lower()
                if dom not in redir_host:
                    return {{"success": False, "http_code": resp.status_code,
                             "latency_ms": elapsed*1000,
                             "content_len": clen, "content_ok": False,
                             "throttled": False, "read_rate_bps": rate,
                             "error": "suspicious redirect " + str(resp.status_code)
                                      + " to " + loc[:80]}}
        if resp.status_code == 400:
            return {{"success": False, "http_code": 400,
                     "latency_ms": elapsed*1000,
                     "content_len": clen, "content_ok": False,
                     "throttled": False, "read_rate_bps": rate,
                     "error": "http 400 (likely fake packets received)"}}
        content_ok = clen >= 300
        dpi_fake = any(p in body.lower() for p in (b"roskomnadzor",b"rkn.gov.ru",
                    b"blockpage",b"utmblock"))
        if dpi_fake:
            content_ok = False
        # 206 only counts as "small body OK" when the body is actually small;
        # googlevideo Range replies are 206 with ~17KB — must apply rate bands.
        small_codes = (101, 204, 301, 302, 303, 304, 307, 308)
        small_body_ok = (not dpi_fake) and (
            resp.status_code in small_codes
            or (resp.status_code == 206 and clen < 300)
        )
        status_ok = (200 <= resp.status_code < 400)
        throttled = False
        success = False
        if status_ok and (content_ok or small_body_ok) and not dpi_fake:
            if rate < {MIN_READ_RATE_BPS} and not small_body_ok:
                success = False
            elif rate < {THROTTLED_MAX_BPS} and not small_body_ok and clen >= 300:
                success = True
                throttled = True
            else:
                success = True
        return {{"success": success, "http_code": resp.status_code,
                 "latency_ms": elapsed*1000,
                 "content_len": clen, "content_ok": content_ok,
                 "throttled": throttled, "read_rate_bps": rate, "error": None}}
    except Exception as e:
        return {{"success": False, "http_code": 0, "latency_ms": 0,
                 "content_len": 0, "content_ok": False,
                 "throttled": False, "read_rate_bps": 0, "error": str(e)[:120]}}
def run_checks():
    n = {repeats}
    if {parallel_int}:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            futs = [ex.submit(check, {domain!r}, {timeout}, {resolved_ip_lit}) for _ in range(n)]
            last = None
            for fut in concurrent.futures.as_completed(futs):
                last = fut.result()
                if last.get("success"):
                    return last
            return last or {{"success": False, "http_code": 0, "latency_ms": 0,
                             "content_len": 0, "content_ok": False,
                             "throttled": False, "read_rate_bps": 0,
                             "error": "all parallel repeats failed"}}
    last = None
    for _ in range(n):
        last = check({domain!r}, {timeout}, {resolved_ip_lit})
        if last.get("success"):
            return last
    return last
print(json.dumps(run_checks()))
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
            "--qnum=201",
            "--filter-l3=ipv4",
            "--ipcache-lifetime=0",
            "--bind-fix4",
        ]
        for lua in ["/opt/zapret2/lua/zapret-lib.lua", "/opt/zapret2/lua/zapret-antidpi.lua"]:
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
            "--qnum=201",
            "--filter-udp=50000-50100",
            "--filter-l3=ipv4",
            "--ipcache-lifetime=0",
            "--bind-fix4",
        ]
        for lua in ["/opt/zapret2/lua/zapret-lib.lua", "/opt/zapret2/lua/zapret-antidpi.lua"]:
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
        "201",
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
        db: StateDB = None,
        python_path: str = None,
        disable_ech: bool = False,
        secure_dns: bool = True,
        dns_cache: DnsRunCache | None = None,
        dns_audit: dict | None = None,
        repeats: int = 1,
        parallel_repeats: bool = False,
        try_wssize: bool = False,
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
        self.repeats = max(1, repeats)
        self.parallel_repeats = parallel_repeats
        self.try_wssize = try_wssize

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
        from blockchecks.engine.db_logger import Checkpoint

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

        # Resume: skip completed pairs based on checkpoint labels
        resume_tcp_label = None
        resume_udp_label = None
        if isinstance(resume_from, Checkpoint):
            resume_tcp_label = resume_from.tcp_label or None
            resume_udp_label = resume_from.udp_label or None
        elif resume_from is not None and hasattr(resume_from, "tcp_label"):
            resume_tcp_label = getattr(resume_from, "tcp_label", None) or None
            resume_udp_label = getattr(resume_from, "udp_label", None) or None
        if resume_tcp_label:
            print(f"  {YELLOW}Resuming after {resume_tcp_label}+{resume_udp_label}{RESET}")
        print(
            f"  {CYAN}Pair matrix: {len(working)} TCP × {len(udp_strategies)} UDP "
            f"= {total} pairs, {self.pool.size} parallel{RESET}"
        )

        async def run_pair(tcp_i: int, tcp_r: TcpTestResult, udp_s: StrategyItem, pair_idx: int):
            # Resume skip — inclusive of last completed pair
            if resume_tcp_label and resume_udp_label:
                if tcp_r.item.label < resume_tcp_label:
                    return
                if tcp_r.item.label == resume_tcp_label and udp_s.label <= resume_udp_label:
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
        pair_idx = 0
        for tcp_i, tcp_r in working:
            for udp_s in udp_strategies:
                pair_idx += 1
                tasks.append(asyncio.create_task(run_pair(tcp_i, tcp_r, udp_s, pair_idx - 1)))

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
