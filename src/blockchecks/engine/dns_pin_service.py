"""Auto-pin DNS candidates and persist working IPs to disk."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from blockchecks.checkers.dns_secure import DnsRunCache
from blockchecks.engine.config import PIN_TIMEOUT, PYTHON_BIN
from blockchecks.engine.fail_phase import FailPhase
from blockchecks.service.in_ns_workers import _run_tcp_check
from blockchecks.terminal import CYAN, RESET, YELLOW

log = logging.getLogger(__name__)

PIN_STRATEGY = "fake:blob=stun:repeats=6:tcp_ts=-1000"
PIN_SETTLE_MAX = 0.5
_L3_SKIP_PIN = frozenset({FailPhase.L4_SYN_DROP, FailPhase.ICMP_BLOCK})


def pin_candidate_l3_ok(ip: str) -> bool:
    """False when SYN is dropped or ICMP-filtered — skip expensive stun L7."""
    from blockchecks.checkers.l3_probe import probe_l3

    return probe_l3(ip, 443, timeout=min(PIN_TIMEOUT, 1.5), use_raw=True).phase not in _L3_SKIP_PIN


class DnsPinService:
    """Probe DoH/pinned IPs and write only changed pins back to disk."""

    def __init__(
        self,
        *,
        dns_cache: DnsRunCache,
        pinned_path: str,
        python_path: str = PYTHON_BIN,
        disable_ech: bool = False,
        acquire_ns: Callable[[], Awaitable[str]],
        release_ns: Callable[[str], Awaitable[None]],
    ) -> None:
        self.dns_cache = dns_cache
        self.pinned_path = pinned_path
        self.python = python_path
        self.disable_ech = disable_ech
        self._acquire_ns = acquire_ns
        self._release_ns = release_ns

    async def auto_pin_ips(
        self,
        probe: Callable[[str, str], Awaitable[bool]] | None = None,
        l3_ok: Callable[[str], bool] | None = None,
    ) -> None:
        """Probe candidates with the known-good fake strategy; pin first PASS."""
        from blockchecks.checkers.ip_pin import load_pins, merge_pins, save_pins

        probe_fn = probe or self.probe_pin_ip
        l3_fn = l3_ok or pin_candidate_l3_ok

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
                if not l3_fn(ip):
                    continue
                if await probe_fn(domain, ip):
                    picked = ip
                    break
            if picked:
                updates[domain] = picked
                if self.dns_cache.pinned_ip(domain) != picked:
                    self.dns_cache.add_pin(domain, picked)
                tag = "file" if existing == picked else "auto"
                log.info("%s", f"  {CYAN}[dns] pinned {domain} -> {picked} ({tag}){RESET}")
            elif existing:
                self.dns_cache.add_pin(domain, existing)
                log.info(
                    "%s",
                    f"  {YELLOW}[dns] pin kept for {domain} -> {existing} "
                    f"(no working fallback){RESET}",
                )

        if not self.pinned_path:
            return

        merged = merge_pins(file_pins, updates)
        if merged != file_pins:
            try:
                save_pins(self.pinned_path, merged)
                log.info("%s", f"  {CYAN}[dns] saved pinned IPs -> {self.pinned_path}{RESET}")
            except OSError as e:
                log.info("%s", f"  {YELLOW}[dns] cannot save pins {self.pinned_path}: {e}{RESET}")
        else:
            log.info("%s", f"  {CYAN}[dns] pins unchanged -> {self.pinned_path}{RESET}")

    async def probe_pin_ip(self, domain: str, ip: str) -> bool:
        """Return True when ``fake:blob=stun`` passes to *domain* via *ip*."""
        ns = await self._acquire_ns()
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
            await self._release_ns(ns)
