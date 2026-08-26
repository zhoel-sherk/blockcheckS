"""TCP×UDP pair matrix orchestration for AsyncTestRunner."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from blockchecks.engine.matrix_generator import StrategyItem
from blockchecks.engine.results import PairResult, TcpTestResult
from blockchecks.terminal import CYAN, GREEN, RED, RESET, YELLOW

if TYPE_CHECKING:
    from blockchecks.engine.store import RunStateStore
    from blockchecks.engine.store.models import Checkpoint
    from blockchecks.service.netns_pool import NetNsPool

log = logging.getLogger(__name__)


def _run_tcp_check(*args, **kwargs):
    from blockchecks.engine.async_runner import _run_tcp_check as fn

    return fn(*args, **kwargs)


def _run_udp_check(*args, **kwargs):
    from blockchecks.engine.async_runner import _run_udp_check as fn

    return fn(*args, **kwargs)


def _save_pass_strategy_data_block(*args, **kwargs):
    from blockchecks.engine.async_runner import _save_pass_strategy_data_block as fn

    return fn(*args, **kwargs)


class PairMatrixRunner:
    """Parallel UDP probes for each PASS TCP × each UDP strategy."""

    def __init__(
        self,
        pool: NetNsPool,
        db: RunStateStore | None,
        *,
        python: str,
        disable_ech: bool,
        matrix_fingerprint: str = "",
    ) -> None:
        self.pool = pool
        self.db = db
        self.python = python
        self.disable_ech = disable_ech
        self.matrix_fingerprint = matrix_fingerprint

    async def run(
        self,
        tcp_results: list[TcpTestResult],
        udp_strategies: list[StrategyItem],
        domain: str,
        voice_ip: str,
        voice_port: int,
        udp_timeout: float = 3.0,
        udp_bypass: bool = False,
        resume_from: Checkpoint | None = None,
        full_voice: bool = False,
        fingerprint: str = "",
        *,
        pair_domain: str | None = None,
    ) -> list[PairResult]:
        """Run pair matrix; TCP nfqws2 once per pair, UDP nfqws2 per strategy.

        ``pair_domain`` overrides the domain key used for pair_results /
        resume (e.g. ``discord.com@1.2.3.4:50004`` for multi-EP fan-out);
        TCP curl still uses ``domain``.
        """
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

        completed: set[tuple[str, str]] = set()
        if self.db:
            try:
                completed = await self.db.get_completed_pair_keys(log_domain)
            except Exception as exc:
                log.warning("%s", f"  WARNING: pair resume keys unavailable ({exc})")
                completed = set()
        from blockchecks.engine.store.models import Checkpoint

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
                        True,
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
