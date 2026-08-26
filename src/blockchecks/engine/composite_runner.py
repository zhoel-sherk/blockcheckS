"""Run every domain in an nfqws2 config with one netns and one daemon.
Hostlists already split traffic, so one process covers the full set.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from pathlib import Path

from blockchecks.checkers.curl_probe import CurlProbeRequest, worker_wall_timeout
from blockchecks.engine.config import NETNS_BASE, NFQUEUE_UDP, SHM_BASE
from blockchecks.engine.config import PYTHON_BIN as PYTHON
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.results import TcpTestResult
from blockchecks.service.netns_pool import NetNsPool
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


async def _start_pool(pool: NetNsPool) -> None:
    await asyncio.to_thread(pool.create_all)
    await pool.seed()


async def _stop_pool(pool: NetNsPool) -> None:
    await pool.drain()
    await asyncio.to_thread(pool.destroy_all)


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

    # One netns + one nfqws2 for ALL domains (NetNsPool only; no AsyncTestRunner).
    pool = NetNsPool(size=1, base=f"{NETNS_BASE}-{os.getpid() % 10000:04d}")
    await _start_pool(pool)
    ns_name = await pool.acquire()

    # RT-композит: ждём первый heartbeat демона (Lua-таймер ~200мс) до первой
    # пробы — иначе проба уходит в окно Lua-init при queue-bypass и ТСПУ
    # дропает её (ложный таймаут).
    # Каталог IPC обязан существовать ДО старта демона и быть доступным
    # overflow-uid (иначе Lua не пишет heartbeat/стратегию — мост мёртв).
    _shm_dir = Path(SHM_BASE) / ns_name
    try:
        _shm_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(_shm_dir, 0o777)
    except OSError as exc:
        log.warning("composite: shm dir %s prepare failed: %s", _shm_dir, exc)

    # Ждём ФАКТИЧЕСКОГО бинда очереди: маркер 'setting copy_packet mode'
    # в stdout-захвате демона (надёжен при любом пользователе запуска,
    # в отличие от /proc-скана root-owned процессов).
    hb_path = Path(SHM_BASE) / ns_name / "heartbeat"  # noqa: F841 (IPC будущ.)
    _bind_deadline = time.perf_counter() + 12.0
    _bound = False
    while time.perf_counter() < _bind_deadline:
        try:
            outs = sorted(Path(SHM_BASE).glob("../state/blockcheckS/logs/nfqws2_out_"
                          f"{ns_name}_*.log")) if False else []
        except Exception:
            outs = []
        # путь захвата берём из RUNTIME_LOGS_DIR напрямую
        from blockchecks.engine.paths import RUNTIME_LOGS_DIR
        candidates = sorted(
            RUNTIME_LOGS_DIR.glob(f"nfqws2_out_{ns_name}_*.log"),
            key=lambda q: q.stat().st_mtime,
        )
        if candidates:
            try:
                txt = candidates[-1].read_text(errors="replace")[-800:]
            except OSError:
                txt = ""
            if "setting copy_packet mode" in txt:
                _bound = True
                break
        time.sleep(0.15)
    if not _bound:
        log.warning(
            "composite: queue-bind marker not seen within 12s (%s) — probing anyway",
            ns_name,
        )

    # Автоинъекция окружения для `-c` конфигов: их часто пишут минимально,
    # без --lua-init/--qnum, что раньше давало мгновенную смерть демона
    # ("desync function does not exist" / "Need queue number").
    mod_conf: str | None = None
    try:
        conf_text = Path(config_abs).read_text(encoding="utf-8")
        inject: list[str] = []
        from blockchecks.engine.config import NFQUEUE_TCP, get_lua_init_scripts

        if "--lua-init=" not in conf_text:
            inject += [f"--lua-init=@{p}" for p in get_lua_init_scripts()]
        if "--qnum=" not in conf_text:
            inject.append(f"--qnum={NFQUEUE_TCP}")
        if inject:
            mod_conf = f"{config_abs}.composite.{os.getpid()}.conf"
            Path(mod_conf).write_text(
                "\n".join(inject) + "\n" + conf_text, encoding="utf-8"
            )
            log.info("%s", f"  composite: injected {len(inject)} env lines into config copy")
            config_abs = mod_conf
    except OSError as exc:
        log.warning("composite config injection skipped: %s", exc)

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
            # DNS внутри ns идёт plaintext-UDP и подвержен подмене ТСПУ;
            # резолвим через DoH и пинним IP (как делает основной путь).
            resolved_ip: str | None = None
            try:
                from blockchecks.checkers.dns_secure import (
                    doh_query,
                    pick_working_doh,
                )

                _doh = pick_working_doh()
                _ips, _err, _ = doh_query(domain, _doh, timeout=min(timeout, 5.0))
                if _ips and not _err:
                    resolved_ip = _ips[0]
            except Exception as exc:
                log.warning("composite DoH %s failed: %s", domain, exc)
            payload = {
                "mode": "single",
                "request": probe_request_dict(
                    CurlProbeRequest(
                        domain=domain,
                        timeout=timeout,
                        resolved_ip=resolved_ip,
                        resolve_name=domain.split("/")[0],
                    )
                ),
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
        await pool.release(ns_name)
        if mod_conf:
            try:
                os.unlink(mod_conf)
            except OSError:
                pass
        await _stop_pool(pool)

    elapsed = time.perf_counter() - t0
    passed = sum(1 for r in results if r.success)
    log.info("%s", f"\n  {passed}/{len(results)} passed in {elapsed:.1f}s")
    return 0 if passed > 0 else 1
