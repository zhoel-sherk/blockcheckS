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
from typing import Optional

from colorama import Fore, Style, init as colorama_init
colorama_init(autoreset=True)

from engine.db_logger import StateDB
from engine.netns_pool import NetNsPool

GREEN = Fore.GREEN + Style.BRIGHT
RED = Fore.RED + Style.BRIGHT
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
GREY = Fore.LIGHTBLACK_EX
RESET = Style.RESET_ALL

GREEN = Fore.GREEN + Style.BRIGHT
RED = Fore.RED + Style.BRIGHT
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
GREY = Fore.LIGHTBLACK_EX
RESET = Style.RESET_ALL

NFQWS2_BIN = "/opt/zapret2/nfq2/nfqws2"


@dataclass
class StrategyItem:
    label: str
    strategy: str  # inline strategy string OR path to .conf file
    is_config: bool = False  # True if this is a file path (use @path syntax)


@dataclass
class TcpTestResult:
    item: StrategyItem
    domain: str
    success: bool = False
    http_code: int = 0
    latency_ms: float = 0
    content_length: int = 0
    content_valid: bool = True
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
    import subprocess as sp
    r = sp.run(["sudo"] + list(args), capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        raise RuntimeError(f"sudo {' '.join(args)}: {r.stderr[:200]}")
    return r.stdout.strip()


def _nfqws2_daemon(ns_name: str, config_path: str) -> None:
    """Launch nfqws2 in daemon mode inside ns. Non-blocking."""
    import subprocess as sp
    cmd = ["sudo", "ip", "netns", "exec", ns_name, NFQWS2_BIN,
           f"@{config_path}", "--daemon"]
    proc = sp.Popen(cmd, stdout=sp.DEVNULL, stderr=sp.PIPE)
    time.sleep(0.8)
    r = sp.run(["sudo", "ip", "netns", "exec", ns_name,
                "pgrep", "-x", "nfqws2"], capture_output=True, text=True, timeout=5)
    if r.returncode != 0:
        stderr = ""
        try: stderr = proc.stderr.read().decode() if proc.stderr else ""
        except: pass
        raise RuntimeError(f"nfqws2 failed to start: {stderr[:200]}")


def _add_blobs_from_strategy(lines: list[str], strategy: str) -> None:
    """Parse strategy string for blob:NAME references, add --blob=NAME:@/path."""
    import re
    BLOB_DIR = "/opt/zapret2/blobs"
    known = sorted(f for f in os.listdir(BLOB_DIR) if f.endswith(".bin"))
    for m in re.finditer(r"blob=(\w+)", strategy):
        name = m.group(1)
        if name == "0x00000000":
            continue
        # Prefer TLS/Stun blobs over QUIC for TCP strategies
        candidates = [f for f in known if name in f and "quic_initial" not in f]
        if not candidates:
            candidates = [f for f in known if name in f]
        if candidates:
            fname = candidates[0]
            if any(l.startswith(f"--blob={name}:@") for l in lines):
                break
            lines.append(f"--blob={name}:@{BLOB_DIR}/{fname}")
            break


# ── In-namespace test workers (sync, called via asyncio.to_thread) ──

def _run_tcp_check(ns_name: str, strategy: str, domain: str,
                   timeout: float, is_config: bool = False) -> dict:
    """Start nfqws2 in ns, run curl_cffi check, return result dict."""
    import subprocess as sp

    # Setup nfqws2
    if is_config:
        config_path = os.path.abspath(strategy) if not os.path.isabs(strategy) else strategy
        _nfqws2_daemon(ns_name, config_path)
    else:
        # Build config from inline strategy
        config_lines = [
            "--qnum=200", "--filter-tcp=443", "--filter-l3=ipv4",
            "--filter-l7=tls", "--ipcache-lifetime=0", "--bind-fix4",
        ]
        for lua in ["/opt/zapret2/lua/zapret-lib.lua",
                     "/opt/zapret2/lua/zapret-antidpi.lua"]:
            if os.path.exists(lua):
                config_lines.append(f"--lua-init=@{lua}")
        # Auto-detect blobs referenced in strategy string
        _add_blobs_from_strategy(config_lines, strategy)
        # Strategy may already contain nfqws2 CLI args (from custom lists)
        # or just the lua-desync value (from generators)
        # Multi-strategy separated by \n. Full CLI args split on ' --' boundaries.
        for raw_line in strategy.split("\n"):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            if raw_line.startswith("--"):
                # Full CLI args — split into individual args
                # e.g., "--payload tls_client_hello --lua-desync=syndata --lua-desync=hostfakesplit:..."
                for arg in raw_line.split(" --"):
                    arg = arg.strip()
                    if not arg:
                        continue
                    if not arg.startswith("--"):
                        arg = "--" + arg
                    config_lines.append(arg)
            else:
                config_lines.append(f"--lua-desync={raw_line}")
        tmp_conf = f"/tmp/bs_async_{os.getpid()}_{int(time.time())}.conf"
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        _nfqws2_daemon(ns_name, tmp_conf)
        config_path = tmp_conf

    # Add iptables rule
    _sudo("ip", "netns", "exec", ns_name, "iptables", "-A", "OUTPUT",
          "-p", "tcp", "--dport", "443", "-j", "NFQUEUE", "--queue-num", "200")

    # Run curl_cffi check as inline Python — two-phase:
    # Phase 1: quick GET with 1.5s timeout → validates TLS
    # Phase 2: full body download → validates no window clamping
    check_code = f"""
import json, time
def check(domain, timeout):
    try:
        import curl_cffi
        # Phase 1: quick probe
        start = time.perf_counter()
        try:
            resp = curl_cffi.get(
                "https://{domain}", impersonate="chrome124", http_version=2,
                timeout=min({timeout}, 1.5), headers={{"Accept":"text/html"}},
                allow_redirects=False,
            )
        except curl_cffi.CurlError as e:
            msg = str(e)
            return {{"success": False, "http_code": 0,
                      "latency_ms": (time.perf_counter()-start)*1000,
                      "content_len": 0, "content_ok": False,
                      "error": "timeout" if "Timeout" in msg else msg[:120]}}
        body = resp.content[:4096]
        clen = len(resp.content)
        content_ok = clen >= 300
        dpi_fake = any(p in body.lower() for p in (b"roskomnadzor",b"rkn.gov.ru",
                    b"blockpage",b"utmblock"))
        if dpi_fake: content_ok = False
        small_body_ok = resp.status_code in (101,204,301,302,303,304,307,308,206)
        success = (200 <= resp.status_code < 400) and (content_ok or small_body_ok)
        return {{"success": success, "http_code": resp.status_code,
                 "latency_ms": (time.perf_counter()-start)*1000,
                 "content_len": clen, "content_ok": content_ok, "error": None}}
    except curl_cffi.CurlError as e:
        msg = str(e)
        return {{"success": False, "http_code": 0,
                 "latency_ms": (time.perf_counter()-start)*1000,
                 "content_len": 0, "content_ok": False,
                 "error": "timeout" if "Timeout" in msg else msg[:120]}}
    except Exception as e:
        return {{"success": False, "http_code": 0, "latency_ms": 0,
                 "content_len": 0, "content_ok": False, "error": str(e)[:120]}}
print(json.dumps(check("{domain}", {timeout})))
"""
    r = sp.run(
        ["sudo", "ip", "netns", "exec", ns_name,
         "/home/zhoel/workspace/dpi-tester/.venv/bin/python", "-c", check_code],
        capture_output=True, text=True, timeout=timeout + 10
    )
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"success": False, "http_code": 0, "latency_ms": 0,
                "content_len": 0, "content_ok": False,
                "error": f"parse: {r.stdout[:100]}"}


def _run_udp_check(ns_name: str, strategy: str, ip: str, port: int,
                   timeout: float, is_config: bool = False) -> dict:
    """Start nfqws2 UDP in ns, run STUN probe, return result."""
    import subprocess as sp

    if is_config:
        _nfqws2_daemon(ns_name, strategy)
    else:
        config_lines = [
            "--qnum=201", "--filter-udp=50000-50100", "--filter-l3=ipv4",
            "--filter-l7=discord,stun", "--ipcache-lifetime=0", "--bind-fix4",
        ]
        for lua in ["/opt/zapret2/lua/zapret-lib.lua",
                     "/opt/zapret2/lua/zapret-antidpi.lua"]:
            if os.path.exists(lua):
                config_lines.append(f"--lua-init=@{lua}")
        blob = "/opt/zapret2/blobs/discord_udp.bin"
        if os.path.exists(blob):
            config_lines.append(f"--blob=discord_udp:@{blob}")
        config_lines.append(f"--lua-desync={strategy}")
        tmp_conf = f"/tmp/bs_async_udp_{os.getpid()}_{int(time.time())}.conf"
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        _nfqws2_daemon(ns_name, tmp_conf)

    _sudo("ip", "netns", "exec", ns_name, "iptables", "-A", "OUTPUT",
          "-p", "udp", "--dport", str(port), "-j", "NFQUEUE",
          "--queue-num", "201")

    probe_code = f"""
import json, socket, struct, time
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout({timeout})
    msg = struct.pack(">HHI", 0x0001, 0x0000, 0x2112A442)+b"\\x00"*12
    start = time.perf_counter()
    sock.sendto(msg, ("{ip}", {port}))
    data, addr = sock.recvfrom(512)
    elapsed = (time.perf_counter()-start)*1000
    sock.close()
    print(json.dumps({{"success": True, "latency_ms": elapsed,
        "detail": f"{{len(data)}}B from {{addr[0]}}:{{addr[1]}}"}}))
except socket.timeout:
    elapsed = (time.perf_counter()-start)*1000
    print(json.dumps({{"success": False, "latency_ms": elapsed, "detail":"timeout"}}))
except Exception as e:
    print(json.dumps({{"success": False, "latency_ms": 0, "detail": str(e)[:100]}}))
"""
    r = sp.run(
        ["sudo", "ip", "netns", "exec", ns_name,
         "/home/zhoel/workspace/dpi-tester/.venv/bin/python", "-c", probe_code],
        capture_output=True, text=True, timeout=timeout + 5
    )
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"success": False, "latency_ms": 0, "detail": "parse error"}

# ── AsyncTestRunner ─────────────────────────────────

class AsyncTestRunner:
    """Parallel strategy tester using NetNsPool + asyncio.Semaphore."""

    def __init__(self, pool_size: int = 4, db: StateDB = None,
                 python_path: str = "/home/zhoel/workspace/dpi-tester/.venv/bin/python"):
        self.pool = NetNsPool(size=pool_size)
        self.semaphore = asyncio.Semaphore(pool_size)
        self.db = db
        self.python = python_path

    async def start(self):
        """Create netns pool."""
        await asyncio.to_thread(self.pool.create_all)

    async def stop(self):
        """Destroy netns pool."""
        await asyncio.to_thread(self.pool.destroy_all)

    async def test_tcp(self, item: StrategyItem, domain: str,
                       timeout: float = 5.0) -> TcpTestResult:
        """Test one TCP strategy in an isolated netns."""
        result = TcpTestResult(item=item, domain=domain)

        async with self.semaphore:
            ns_name = await self.pool.acquire()
            try:
                data = await asyncio.to_thread(
                    _run_tcp_check, ns_name, item.strategy, domain,
                    timeout, item.is_config
                )
                result.success = data.get("success", False)
                result.http_code = data.get("http_code", 0)
                result.latency_ms = data.get("latency_ms", 0)
                result.content_length = data.get("content_len", 0)
                result.content_valid = data.get("content_ok", True)
                result.error = data.get("error", "") or ""

                if self.db:
                    await self.db.log_tcp(
                        item.label, domain,
                        "PASS" if result.success else "FAIL",
                        result.latency_ms, result.http_code,
                        content_valid=result.content_valid,
                        error=result.error,
                    )
            except Exception as e:
                result.error = str(e)[:200]
            finally:
                await self.pool.release(ns_name)

        return result

    async def test_udp(self, item: StrategyItem, ip: str, port: int,
                       timeout: float = 3.0) -> UdpTestResult:
        """Test one UDP strategy."""
        target = f"{ip}:{port}"
        result = UdpTestResult(item=item, target=target)

        async with self.semaphore:
            ns_name = await self.pool.acquire()
            try:
                data = await asyncio.to_thread(
                    _run_udp_check, ns_name, item.strategy, ip, port,
                    timeout, item.is_config
                )
                result.success = data.get("success", False)
                result.latency_ms = data.get("latency_ms", 0)
                result.error = data.get("detail", "") or ""

                if self.db:
                    await self.db.log_udp(
                        item.label, target,
                        "PASS" if result.success else "FAIL",
                        result.latency_ms, result.error,
                    )
            except Exception as e:
                result.error = str(e)[:200]
            finally:
                await self.pool.release(ns_name)

        return result

    async def test_batch_tcp(self, strategies: list[StrategyItem],
                              domain: str, timeout: float = 5.0
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
            tag = f"{GREEN}OK{RESET}" if r.success else f"{RED}FAIL{RESET}"
            lat = f"{r.latency_ms:.0f}ms" if r.latency_ms else ""
            status = f"HTTP {r.http_code}" if r.http_code else ""
            err = f" — {r.error[:40]}" if r.error else ""
            label = r.item.label[:30]
            print(f"  [{tag}] {lat:>6s}  {status:>8s}  {label}{err}")
            results.append(r)

        return list(results)  # maintain order via tasks list

    async def test_pair_matrix(self,
                                tcp_results: list[TcpTestResult],
                                udp_strategies: list[StrategyItem],
                                domain: str,
                                voice_ip: str, voice_port: int,
                                udp_timeout: float = 3.0,
                                udp_bypass: bool = False,
                                ) -> list[PairResult]:
        """Parallel UDP probes for each PASS TCP × each UDP strategy.

        Each pair runs in its own netns via asyncio.create_task + Semaphore.
        TCP nfqws2 started once per pair, UDP nfqws2 per strategy.
        DB writes serialized via asyncio.Lock.
        """
        pairs: list[PairResult] = []
        db_lock = asyncio.Lock()
        pair_sem = asyncio.Semaphore(self.pool.size)

        if udp_bypass:
            working = list(enumerate(tcp_results))
        else:
            working = [(i, r) for i, r in enumerate(tcp_results) if r.success]

        if not working:
            print(f"\n  {RED}No PASS TCP — UDP skipped{RESET}")
            return pairs

        total = len(working) * len(udp_strategies)
        print(f"  {CYAN}Pair matrix: {len(working)} TCP × {len(udp_strategies)} UDP "
              f"= {total} pairs, {self.pool.size} parallel{RESET}")

        async def run_pair(tcp_i: int, tcp_r: TcpTestResult,
                            udp_s: StrategyItem, pair_idx: int):
            async with pair_sem:
                ns_name = await self.pool.acquire()
                try:
                    # Start TCP nfqws2 — uses cached result (already known PASS)
                    await asyncio.to_thread(
                        _run_tcp_check, ns_name,
                        tcp_r.item.strategy, domain, 0.1,
                        tcp_r.item.is_config
                    )
                    # Start UDP nfqws2 on same ns
                    data = await asyncio.to_thread(
                        _run_udp_check, ns_name,
                        udp_s.strategy, voice_ip, voice_port,
                        udp_timeout, udp_s.is_config
                    )
                    udp_ok = data.get("success", False)
                    udp_ms = data.get("latency_ms", 0)

                    pair = PairResult(
                        tcp_item=tcp_r.item, udp_item=udp_s,
                        tcp_ok=tcp_r.success, udp_ok=udp_ok,
                        tcp_ms=tcp_r.latency_ms, udp_ms=udp_ms,
                    )
                    if tcp_r.success and udp_ok:
                        pair.overall = "PASS"
                    elif tcp_r.success and not udp_ok:
                        pair.overall = "PARTIAL"
                    else:
                        pair.overall = "FAIL"

                    pairs.append(pair)

                    pair_tag = {"PASS": f"{GREEN}PASS{RESET}",
                                 "PARTIAL": f"{YELLOW}PARTIAL{RESET}",
                                 "FAIL": f"{RED}FAIL{RESET}"}[pair.overall]
                    udp_tag = f"{GREEN}{udp_ms:.0f}ms{RESET}" if udp_ok else f"{RED}timeout{RESET}"
                    print(f"  [{pair_tag}] {tcp_r.item.label[:22]:22s} "
                          f"+ {udp_s.label[:22]:22s}  udp={udp_tag}")

                    # DB writes serialized via lock
                    if self.db:
                        async with db_lock:
                            await self.db.log_pair(
                                tcp_r.item.label, udp_s.label, domain,
                                tcp_r.success, False, udp_ok,
                                tcp_r.latency_ms, 0, udp_ms, pair.overall,
                            )
                            await self.db.save_checkpoint(
                                tcp_i, pair_idx,
                                f"{tcp_r.item.label}+{udp_s.label}",
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
                tasks.append(
                    asyncio.create_task(
                        run_pair(tcp_i, tcp_r, udp_s, pair_idx - 1)
                    )
                )

        await asyncio.gather(*tasks)
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

        print(f"\n  {CYAN}╔{'═'*60}╗{RESET}")
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
                elif p.overall == "PARTIAL":
                    tag = f"{YELLOW}PARTIAL{RESET}"
                else:
                    tag = f"{RED}FAIL{RESET}"
                udp_lat = f"{p.udp_ms:.0f}ms" if p.udp_ok else "timeout"
                print(f"  {tag:12s} {tcp[:22]:22s} + {udp[:22]:22s}  "
                      f"udp={udp_lat}")

        print(f"  {CYAN}{'═'*60}{RESET}")
        print(f"  {GREEN}{passed} PASS{RESET} / {len(pairs)} pairs")
