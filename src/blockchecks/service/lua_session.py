"""Lua-bridge session: boot, probe window, shutdown."""

from __future__ import annotations

import logging
import os
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from blockchecks.engine.config import NETNS_BASE, SHM_BASE
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.service.lua_bridge_ipc import LuaBridge
from blockchecks.service.lua_conf import write_bridge_conf
from blockchecks.service.lua_netns import (
    NetnsGoneError,
    _bridge_iptables_add,
    _check_netns_exists,
)

log = logging.getLogger(__name__)


@dataclass
class BridgeSession:
    """Per-slot bridge state: one daemon + firewall for a strategy batch.

    ``ns_name`` is either a netns (``bs-p-…``, default isolation) or a
    host-mode slot (``host-q<N>-<pid>``, docs/hostmode.md §9) — detected by
    the canon ``host-q`` prefix, the same convention as ``_worker_cmd``.
    """

    ns_name: str
    strategies: list[str]
    bridge: LuaBridge
    conf_path: str = ""
    iptables_ready: bool = False
    protocol: str = "tls12"
    extra_lua_init: list[str] | None = None
    host_qnum: int = 0
    daemon_proc: object | None = None

    @property
    def is_host(self) -> bool:
        return bool(self.host_qnum)

    def _boot_host(self) -> float:
        """Host slot boot (docs/hostmode.md §18.6): bind proof FIRST, then
        the nft queue attach — with --queue-bypass a dead daemon would else
        pass clean traffic straight through."""
        from blockchecks.service.nfqws2_launcher import daemon_host

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
            host_qnum=self.host_qnum,
        )
        settle, self.daemon_proc = daemon_host(self.conf_path, qnum=self.host_qnum)
        if not self.iptables_ready:
            from blockchecks.service.host_isol import DEFAULT_DPORT, attach_host_queue

            attach_host_queue(
                qnum=self.host_qnum,
                dport=80 if self.protocol == "http" else DEFAULT_DPORT,
            )
            self.iptables_ready = True
        return settle

    def _daemon_alive(self) -> bool:
        """One-daemon-per-run (AUDIT §20 D4b): in Mode A the daemon must NOT
        restart between batches — strategy.cmd swaps plans live. Alive check:
        host slot = Popen + /proc portid; netns = visible pids + fresh heartbeat."""
        from blockchecks.engine.config import BRIDGE_MODE

        if BRIDGE_MODE != "A":
            return False  # Mode B restarts per batch (strategies baked in conf)
        if self.host_qnum:
            from blockchecks.service.host_isol import queue_bound
            from blockchecks.service.nfqws2_launcher import _HOST_PROCS

            proc = _HOST_PROCS.get(self.host_qnum)
            return (
                proc is not None and proc.poll() is None and queue_bound(self.host_qnum)
            )
        from blockchecks.service.metrics import find_nfqws2_pids

        pids = find_nfqws2_pids(self.ns_name)
        if not pids:
            return False
        try:
            age = self.bridge.heartbeat_age()
        except OSError:
            return False
        return age is not None and age <= 2.0

    def boot(self) -> float:
        from blockchecks.service.nfqws2 import start_daemon

        if self._daemon_alive():
            return 0.0
        if self.host_qnum:
            return self._boot_host()
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
            _bridge_iptables_add(self.ns_name, dport, protocol=self.protocol)
            self.iptables_ready = True
        return settle

    def shutdown(self) -> None:
        if self.host_qnum:
            from blockchecks.engine.config import BRIDGE_MODE
            from blockchecks.service.host_isol import detach_host_slot_rule

            if BRIDGE_MODE != "A" or not self._daemon_alive():
                from blockchecks.service.nfqws2_launcher import kill_host_daemon

                kill_host_daemon(self.host_qnum)
                self.daemon_proc = None
                # AUDIT §16 v2 lesson: a queue rule with a DEAD listener lets
                # --queue-bypass pass probes RAW (false FAILs for other slots).
                detach_host_slot_rule(self.host_qnum)
            # Mode A + live daemon: keep it across batches (strategy.cmd swaps
            # the plan); the rule stays with its LIVE listener. Final kill is
            # HostSlotPool.destroy_all / bs stop.
        else:
            from blockchecks.engine.config import BRIDGE_MODE
            from blockchecks.service.metrics import pkill_nfqws2_in_ns

            if BRIDGE_MODE != "A" or not self._daemon_alive():
                pkill_nfqws2_in_ns(self.ns_name)
        # Firewall persists per slot (nft table attach-once) / ns (NsFirewall).
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
            lines.append(raw[len("--lua-desync=") :])
    return "\n".join(lines)


def _campaign_shm_prefix(pid: int) -> str:
    """Netns/IPC dir prefix for a campaign process (matches NetNsPool base)."""
    return f"{NETNS_BASE}-{pid % 10000:04d}-"


def _remove_shm_dir(path: Path, *, context: str) -> None:
    if not path.exists():
        return
    try:
        shutil.rmtree(path)
    except OSError as exc:
        log.warning("IPC rmtree %s failed for %s: %s", context, path, exc)
        return
    if path.exists():
        log.warning("IPC rmtree %s left leftovers at %s", context, path)


def teardown_all_bridge_shm(
    shm_base: Path | None = None,
    *,
    ns_names: list[str] | None = None,
    pid: int | None = None,
) -> None:
    """Remove bridge IPC dirs owned by this campaign (scoped cleanup).

    Only deletes directories for the campaign identified by *pid* (prefix
    ``{NETNS_BASE}-{pid%10000:04d}-``) and/or explicit *ns_names*.  Never
    removes the entire SHM_BASE tree — other campaigns may share it.
    """
    base = Path(shm_base or SHM_BASE)
    if not base.is_dir():
        return

    targets: set[Path] = set()

    if ns_names:
        for ns in ns_names:
            if ns:
                targets.add(base / ns)

    resolved_pid = pid
    if resolved_pid is None:
        from blockchecks.service.run_control import read_active_run

        info = read_active_run()
        if info is not None and info.pid == os.getpid():
            resolved_pid = info.pid

    if resolved_pid is not None:
        prefix = _campaign_shm_prefix(resolved_pid)
        for child in base.iterdir():
            if child.is_dir() and child.name.startswith(prefix):
                targets.add(child)

    if not targets:
        log.warning(
            "teardown_all_bridge_shm: no campaign scope (no pid/lock, no ns_names); "
            "skipping SHM cleanup under %s",
            base,
        )
        return

    for path in sorted(targets):
        _remove_shm_dir(path, context="teardown_all_bridge_shm")


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
