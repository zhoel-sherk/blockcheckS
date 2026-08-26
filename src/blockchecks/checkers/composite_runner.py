"""Run every domain in an nfqws2 config with one netns and one daemon.
Hostlists already split traffic, so one process covers the full set.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time

from blockchecks.checkers.curl_probe import CurlProbeRequest, worker_wall_timeout
from blockchecks.engine.async_runner import (
    AsyncTestRunner,
    StrategyItem,
    TcpTestResult,
)
from blockchecks.engine.config import NFQUEUE_TCP, NFQUEUE_UDP
from blockchecks.engine.config import PYTHON_BIN as PYTHON
from blockchecks.service.nfqws2 import start_daemon
from blockchecks.service.ns_firewall import get_ns_firewall
from blockchecks.service.probe import invoke_curl_probe_worker, probe_request_dict
from blockchecks.terminal import CYAN, GREEN, RED, RESET

log = logging.getLogger(__name__)


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
        log.info("%s", f"{RED}Config not found: {config_abs}{RESET}")
        return 1

    log.info(
        "%s", f"\n{CYAN}composite{RESET}  {os.path.basename(config_abs)}  {len(domains)} domains"
    )
    log.info("")

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

        fw = get_ns_firewall(ns_name)
        fw.attach(proto="tcp", port="443", queue=NFQUEUE_TCP)
        fw.attach(proto="udp", port="50000:50100", queue=NFQUEUE_UDP, multiport=True)

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
                log.info("%s", f"  {RED}FAIL{RESET}  {domain}  — invalid domain")
                continue
            payload = {
                "mode": "single",
                "request": probe_request_dict(CurlProbeRequest(domain=domain, timeout=timeout)),
                "repeats": 1,
                "parallel_repeats": False,
                "repeats_mode": "fast",
                "quick_break": False,
            }
            wall = worker_wall_timeout(timeout, 1, settle_slack=3.0)
            data = await asyncio.to_thread(invoke_curl_probe_worker, ns_name, PYTHON, payload, wall)

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
            log.info("%s", f"  {tag}  {domain:30s}  {lat:>8s}  {code_str}{err}")

    finally:
        await runner.pool.release(ns_name)
        await runner.stop()

    elapsed = time.perf_counter() - t0
    passed = sum(1 for r in results if r.success)
    log.info("%s", f"\n  {passed}/{len(results)} passed in {elapsed:.1f}s")
    return 0 if passed > 0 else 1
