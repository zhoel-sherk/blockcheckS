"""Resident probe service — on-the-fly domain/strategy testing.

Holds one warm NetNsPool + AsyncTestRunner so external apps (e.g.
gp-control-plane) can request a domain/strategy probe without paying the
netns/bridge boot cost per call. Fair exclusion via run_control: while a
long-term campaign owns run.lock, every probe request is rejected with
``busy/campaign_active`` instead of blocking forever.

Transport (service/daemon layer): Unix socket core (asyncio.start_unix_server)
with a thin HTTP bridge. This module is the probe *core* — no server code.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from blockchecks.engine.async_runner import AsyncTestRunner
from blockchecks.engine.config import DEFAULT_POOL_SIZE
from blockchecks.engine.fail_phase import classify_fail_phase
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.results import TcpTestResult
from blockchecks.service.run_control import read_active_run

if TYPE_CHECKING:
    from blockchecks.checkers.dns_secure import DnsRunCache
    from blockchecks.engine.store import RunStateStore

# ── fail_phase classifier imported from engine.fail_phase (single source) ──


@dataclass
class ProbeResult:
    """Normalized on-the-fly probe result (JSON-safe contract)."""

    domain: str
    strategy_id: str
    status: str  # PASS | FAIL | THROTTLED
    fail_phase: str = ""
    latency_ms: float = 0.0
    http_code: int = 0
    fingerprint_matched: bool = False
    error: str = ""

    @classmethod
    def from_tcp_result(cls, r: TcpTestResult) -> ProbeResult:
        status = "PASS" if r.success else ("THROTTLED" if r.throttled else "FAIL")
        phase = classify_fail_phase(r.error, r.http_code)
        return cls(
            domain=r.domain,
            strategy_id=r.item.label,
            status=status,
            fail_phase="" if r.success else phase.value,
            latency_ms=round(r.latency_ms, 1),
            http_code=r.http_code,
            fingerprint_matched=bool(r.content_valid and r.http_code),
            error=r.error[:200],
        )

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "strategy_id": self.strategy_id,
            "status": self.status,
            "fail_phase": self.fail_phase,
            "latency_ms": self.latency_ms,
            "http_code": self.http_code,
            "fingerprint_matched": self.fingerprint_matched,
            "error": self.error,
        }


@dataclass
class ProbeRequest:
    """Normalized on-the-fly probe request."""

    domains: list[str]
    strategies: list[str]  # strategy strings or labels
    protocol: str = "tls12"
    timeout: float = 3.0
    repeats: int = 1


class ProbeService:
    """Warm-pool probe service: one AsyncTestRunner kept resident.

    ``start()`` builds the pool + DoH cache; ``probe()`` runs a batch and
    returns normalized results; ``stop()`` drains the pool.
    """

    def __init__(
        self,
        *,
        pool_size: int | None = None,
        db: RunStateStore | None = None,
        dns_cache: DnsRunCache | None = None,
        secure_dns: bool = True,
        lua_bridge: bool | None = None,
        bridge_batch: int = 500,
        lua_extra: list[str] | None = None,
        python_path: str | None = None,
        default_timeout: float = 3.0,
    ):
        self.pool_size = int(pool_size or DEFAULT_POOL_SIZE)
        self.db = db
        self.dns_cache = dns_cache
        self.secure_dns = secure_dns
        self.bridge_batch = int(bridge_batch)
        self.lua_extra = list(lua_extra or [])
        self.python_path = python_path
        self.lua_bridge = True if lua_bridge is None else bool(lua_bridge)
        self.default_timeout = float(default_timeout or 3.0)
        self.runner: AsyncTestRunner | None = None
        self.started = False
        self._lock = asyncio.Lock()
        self._started_mono: float = 0.0

    @property
    def uptime(self) -> float:
        if not self.started or not self._started_mono:
            return 0.0
        return time.monotonic() - self._started_mono

    async def start(self) -> None:
        """Create + warm the netns pool and runner (idempotent)."""
        if self.started:
            return
        self.runner = AsyncTestRunner(
            pool_size=self.pool_size,
            db=self.db,
            disable_ech=False,
            secure_dns=self.secure_dns,
            dns_cache=self.dns_cache,
            dns_audit={},
            pinned_path="",
            auto_pin=False,
            repeats=1,
            lua_bridge=self.lua_bridge,
            bridge_batch=self.bridge_batch,
            lua_extra=self.lua_extra,
            python_path=self.python_path,
        )
        await self.runner.start()
        self.started = True
        self._started_mono = time.monotonic()

    async def stop(self) -> None:
        """Drain pool and destroy namespaces."""
        if self.runner is not None:
            await self.runner.stop()
        self.started = False
        self.runner = None

    @property
    def active_run(self) -> str | None:
        """Name of a competing long-term campaign, or None if pool is free."""
        info = read_active_run()
        if info is None:
            return None
        cmd = (info.command or "").strip()
        if cmd == "serve":
            # the service itself owns run.lock (fair exclusion) — not busy
            return None
        return cmd or f"pid_{info.pid}"

    def busy(self) -> str | None:
        """Return the active campaign id if the pool is owned by a campaign."""
        return self.active_run

    def _items(self, request: ProbeRequest) -> list[StrategyItem]:
        items: list[StrategyItem] = []
        seen: set[str] = set()
        for s in request.strategies:
            key = s.strip()
            if not key or key in seen:
                continue
            seen.add(key)
            items.append(
                StrategyItem(
                    label=key[:60].replace(" ", "_"),
                    strategy=key,
                    protocol=request.protocol,
                )
            )
        return items

    async def probe(self, request: ProbeRequest) -> dict:
        """Run one on-the-fly probe batch. Returns service-level envelope.

        If a long-term campaign owns the pool → 423-style envelope (no probe).
        """
        campaign = self.busy()
        if campaign:
            return {
                "status": "busy",
                "reason": "campaign_active",
                "active_run": campaign,
                "results": [],
            }
        if not self.started:
            await self.start()

        items = self._items(request)
        if not items or not request.domains:
            return {"status": "ok", "results": []}

        results: list[ProbeResult] = []
        async with self._lock:
            for domain in request.domains:
                domain_items = [i for i in items if i.protocol == request.protocol]
                for item in domain_items:
                    r = await self.runner.test_tcp(item, domain, timeout=request.timeout)
                    results.append(ProbeResult.from_tcp_result(r))

        return {
            "status": "ok",
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "results": [r.to_dict() for r in results],
        }
