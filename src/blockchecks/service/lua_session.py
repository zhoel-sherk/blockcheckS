"""Bridge session lifecycle — boot → probe → shutdown for a batch window."""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from blockchecks.engine.config import SHM_BASE
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.service.lua_bridge_ipc import LuaBridge
from blockchecks.service.lua_conf import write_bridge_conf
from blockchecks.service.lua_netns import (
    NetnsGoneError,
    _bridge_iptables_add,
    _check_netns_exists,
)


@dataclass
class BridgeSession:
    """Per-netns bridge state: one daemon + iptables for a strategy batch."""

    ns_name: str
    strategies: list[str]
    bridge: LuaBridge
    conf_path: str = ""
    iptables_ready: bool = False
    protocol: str = "tls12"
    extra_lua_init: list[str] | None = None

    def boot(self) -> float:
        from blockchecks.service.nfqws2 import start_daemon

        _check_netns_exists(self.ns_name)
        self.bridge.setup()
        if self.conf_path:
            try:
                os.unlink(self.conf_path)
            except OSError:
                pass
        self.conf_path = write_bridge_conf(
            self.strategies,
            self.bridge.paths.base,
            protocol=self.protocol,
            extra_lua_init=self.extra_lua_init,
            tag=self.ns_name,
        )
        settle = start_daemon(self.ns_name, self.conf_path, kill_existing=True)
        if not self.iptables_ready:
            dport = "80" if self.protocol == "http" else "443"
            _bridge_iptables_add(self.ns_name, dport)
            self.iptables_ready = True
        return settle

    def shutdown(self) -> None:
        import subprocess as sp

        sp.run(
            ["sudo", "ip", "netns", "exec", self.ns_name, "pkill", "-9", "nfqws2"],
            capture_output=True,
            check=False,
            timeout=15,
        )
        if self.iptables_ready:
            sp.run(
                ["sudo", "ip", "netns", "exec", self.ns_name, "iptables", "-F", "OUTPUT"],
                capture_output=True,
                check=False,
                timeout=15,
            )
            self.iptables_ready = False
        if self.conf_path:
            try:
                os.unlink(self.conf_path)
            except OSError:
                pass
            self.conf_path = ""
        self.bridge.teardown()


def strategy_text_from_item(item: StrategyItem) -> str:
    """Inline strategy or lua-desync lines extracted from a .conf path."""
    if not item.is_config:
        return item.strategy
    lines: list[str] = []
    for raw in Path(item.strategy).read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if raw.startswith("--lua-desync="):
            lines.append(raw[len("--lua-desync="):])
    return "\n".join(lines)


def teardown_all_bridge_shm(shm_base: Path | None = None) -> None:
    """Remove all bridge IPC dirs under SHM_BASE (campaign stop cleanup)."""
    base = Path(shm_base or SHM_BASE)
    if base.is_dir():
        shutil.rmtree(base, ignore_errors=True)


@contextmanager
def bridge_worker_session(
    ns_name: str,
    strategies: list[str],
    *,
    protocol: str = "tls12",
    extra_lua_init: list[str] | None = None,
    shm_base: Path | None = None,
) -> Iterator[BridgeSession]:
    session = BridgeSession(
        ns_name=ns_name,
        strategies=strategies,
        bridge=LuaBridge(ns_name, shm_base=shm_base),
        protocol=protocol,
        extra_lua_init=extra_lua_init,
    )
    try:
        session.boot()
        yield session
    finally:
        session.shutdown()


def chunk_strategies(strategies: list, batch_size: int) -> list[list]:
    """Split strategy list into batches capped at DEFAULT_BRIDGE_BATCH_MAX."""
    from blockchecks.service.batch_scheduler import BatchScheduler

    return BatchScheduler(batch_size).iter_batches(strategies)


__all__ = [
    "BridgeSession",
    "NetnsGoneError",
    "bridge_worker_session",
    "chunk_strategies",
    "strategy_text_from_item",
    "teardown_all_bridge_shm",
]
