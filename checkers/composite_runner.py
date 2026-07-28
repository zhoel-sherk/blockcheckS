"""Test a composite nfqws2 config against all its target domains.

Uses ONE netns + ONE nfqws2 for all domains — the config already
profiles traffic by hostlist, so one instance handles everything.
"""

import asyncio
import json
import os
import subprocess as sp
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.async_runner import AsyncTestRunner, StrategyItem, TcpTestResult
from engine.async_runner import _nfqws2_daemon as start_nfqws2
from colorama import Fore, Style, init as colorama_init
colorama_init(autoreset=True)

GREEN = Fore.GREEN + Style.BRIGHT
RED = Fore.RED + Style.BRIGHT
CYAN = Fore.CYAN
RESET = Style.RESET_ALL

DOMAINS = [
    "discord.com", "discord.gg", "discord.media",
    "discordapp.com", "discordcdn.com", "gateway.discord.gg",
]

from engine.config import PYTHON_BIN as PYTHON

CHECK_CODE = """
import json, time
try:
    import curl_cffi
    start = time.perf_counter()
    resp = curl_cffi.get(
        "https://{domain}", impersonate="chrome124", http_version=2,
        timeout={timeout}, headers={"Accept":"text/html"},
        allow_redirects=False,
    )
    body = resp.content[:4096]
    clen = len(resp.content)
    content_ok = clen >= 300
    dpi_fake = any(p in body.lower() for p in (b"blocked",b"rkn",b"forbidden",
                b"access denied",b"reject",b"filtered",b"blockpage",b"utmblock"))
    if dpi_fake: content_ok = False
    small_body_ok = resp.status_code in (101,204,301,302,303,304,307,308,206)
    success = (200<=resp.status_code<400) and (content_ok or small_body_ok)
    result = dict(success=success, http_code=resp.status_code,
                  latency_ms=(time.perf_counter()-start)*1000,
                  content_len=clen, content_ok=content_ok, error=None)
except curl_cffi.CurlError as e:
    msg = str(e)
    result = dict(success=False, http_code=0,
                  latency_ms=(time.perf_counter()-start)*1000,
                  content_len=0, content_ok=False,
                  error="timeout" if "Timeout" in msg else msg[:120])
except Exception as e:
    result = dict(success=False, http_code=0, latency_ms=0,
                  content_len=0, content_ok=False, error=str(e)[:120])
print(json.dumps(result))
"""


async def run(config_path: str, domains: list[str] = None,
              parallel: int = 2, timeout: float = 5.0):
    if not domains:
        domains = DOMAINS

    config_abs = os.path.abspath(config_path)
    if not os.path.exists(config_abs):
        print(f"{RED}Config not found: {config_abs}{RESET}")
        return 1

    print(f"\n{CYAN}composite{RESET}  {os.path.basename(config_abs)}  "
          f"{len(domains)} domains")
    print()

    # One netns + one nfqws2 for ALL domains
    runner = AsyncTestRunner(pool_size=1)
    await runner.start()
    ns_name = await runner.pool.acquire()

    item = StrategyItem(label="composite", strategy=config_abs, is_config=True)
    t0 = time.perf_counter()
    results = []

    try:
        # Start the single nfqws2 instance
        await asyncio.to_thread(start_nfqws2, ns_name, config_abs)
        await asyncio.sleep(0.5)

        # Add iptables rules inside the netns
        sp.run(["sudo", "ip", "netns", "exec", ns_name,
                "iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "443",
                "-j", "NFQUEUE", "--queue-num", "200"],
               capture_output=True, timeout=5)
        sp.run(["sudo", "ip", "netns", "exec", ns_name,
                "iptables", "-A", "OUTPUT", "-p", "udp", "-m", "multiport",
                "--dports", "50000:50100",
                "-j", "NFQUEUE", "--queue-num", "200"],
               capture_output=True, timeout=5)

        # Test all domains sequentially (sharing one nfqws2)
        for domain in domains:
            code = CHECK_CODE.replace("{domain}", domain).replace(
                "{timeout}", str(timeout))
            r = sp.run(
                ["sudo", "ip", "netns", "exec", ns_name, PYTHON, "-c", code],
                capture_output=True, text=True, timeout=timeout + 10
            )
            try:
                data = json.loads(r.stdout)
            except json.JSONDecodeError:
                data = {"success": False, "http_code": 0, "latency_ms": 0,
                        "error": f"parse: {r.stdout[:100]}"}

            result = TcpTestResult(item=item, domain=domain)
            result.success = data.get("success", False)
            result.http_code = data.get("http_code", 0)
            result.latency_ms = data.get("latency_ms", 0)
            result.error = data.get("error", "") or ""
            results.append(result)

            tag = f"{GREEN}OK{RESET}" if result.success else f"{RED}FAIL{RESET}"
            lat = f"{result.latency_ms:.0f}ms" if result.latency_ms else ""
            code_str = f"HTTP {result.http_code}" if result.http_code else ""
            err = f" — {result.error[:50]}" if result.error else ""
            print(f"  [{tag}] {lat:>7s}  {code_str:>9s}  {domain}{err}")

    finally:
        await runner.pool.release(ns_name)
        try:
            await runner.stop()
        except Exception:
            pass

    passed = sum(1 for r in results if r.success)
    elapsed = time.perf_counter() - t0
    print(f"\n  {GREEN}{passed}/{len(results)} PASS{RESET} in {elapsed:.0f}s")
    return 0 if passed > 0 else 1
