"""Test a composite nfqws2 config against all its target domains.

Uses ONE netns + ONE nfqws2 for all domains — the config already
profiles traffic by hostlist, so one instance handles everything.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess as sp
import time

from colorama import Fore, Style
from colorama import init as colorama_init

from blockchecks.checkers.curl_probe import CurlProbeRequest, worker_wall_timeout
from blockchecks.engine.async_runner import (
    AsyncTestRunner,
    StrategyItem,
    TcpTestResult,
)
from blockchecks.engine.config import NFQUEUE_TCP, NFQUEUE_UDP
from blockchecks.engine.config import PYTHON_BIN as PYTHON
from blockchecks.engine.nfqws2 import start_daemon
from blockchecks.engine.probe import invoke_curl_probe_worker, probe_request_dict

colorama_init(autoreset=True)

GREEN = Fore.GREEN + Style.BRIGHT
RED = Fore.RED + Style.BRIGHT
CYAN = Fore.CYAN
RESET = Style.RESET_ALL

DOMAINS = [
    "discord.com",
    "discord.gg",
    "discord.media",
    "discordapp.com",
    "discordcdn.com",
    "gateway.discord.gg",
]

_FQDN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")


def _valid_domain(domain: str) -> bool:
    return bool(domain) and len(domain) < 253 and _FQDN_RE.match(domain) is not None


def normalize_domains(domains: list[str] | None) -> list[str]:
    """Split comma-separated argv tokens and strip; drop empties; dedupe order-preserving."""
    if not domains:
        return list(DOMAINS)
    out: list[str] = []
    seen: set[str] = set()
    for raw in domains:
        for part in str(raw).split(","):
            d = part.strip()
            if not d or d in seen:
                continue
            seen.add(d)
            out.append(d)
    return out


async def run(
    config_path: str, domains: list[str] = None, _parallel: int = 2, timeout: float = 5.0
):
    domains = normalize_domains(domains)

    config_abs = os.path.abspath(config_path)
    if not os.path.exists(config_abs):
        print(f"{RED}Config not found: {config_abs}{RESET}")
        return 1

    print(f"\n{CYAN}composite{RESET}  {os.path.basename(config_abs)}  {len(domains)} domains")
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
        await asyncio.to_thread(start_daemon, ns_name, config_abs)
        await asyncio.sleep(0.5)

        # Add iptables rules inside the netns
        sp.run(
            [
                "sudo",
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
                "443",
                "-j",
                "NFQUEUE",
                "--queue-num",
                str(NFQUEUE_TCP),
                "--queue-bypass",
            ],
            capture_output=True,
            timeout=5,
        )
        sp.run(
            [
                "sudo",
                "ip",
                "netns",
                "exec",
                ns_name,
                "iptables",
                "-A",
                "OUTPUT",
                "-p",
                "udp",
                "-m",
                "multiport",
                "--dports",
                "50000:50100",
                "-j",
                "NFQUEUE",
                "--queue-num",
                str(NFQUEUE_UDP),
                "--queue-bypass",
            ],
            capture_output=True,
            timeout=5,
        )

        # Test all domains sequentially (sharing one nfqws2) via JSON worker
        for domain in domains:
            if not _valid_domain(domain):
                results.append(
                    TcpTestResult(
                        item=item,
                        domain=domain,
                        success=False,
                        error="invalid domain",
                    )
                )
                print(f"  {RED}FAIL{RESET}  {domain}  — invalid domain")
                continue
            payload = {
                "mode": "single",
                "request": probe_request_dict(
                    CurlProbeRequest(domain=domain, timeout=timeout)
                ),
                "repeats": 1,
                "parallel_repeats": False,
                "repeats_mode": "fast",
                "quick_break": False,
            }
            wall = worker_wall_timeout(timeout, 1, settle_slack=10.0)
            data = await asyncio.to_thread(
                invoke_curl_probe_worker, ns_name, PYTHON, payload, wall
            )

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
            print(f"  {tag}  {domain:30s}  {lat:>8s}  {code_str}{err}")

    finally:
        await runner.pool.release(ns_name)
        await runner.stop()

    elapsed = time.perf_counter() - t0
    passed = sum(1 for r in results if r.success)
    print(f"\n  {passed}/{len(results)} passed in {elapsed:.1f}s")
    return 0 if passed > 0 else 1
