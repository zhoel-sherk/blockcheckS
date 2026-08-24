"""Fixed pool of netns plus veth.
Workers acquire/release. create_all/destroy_all run in a thread; queue ops stay on the event loop.
"""

from __future__ import annotations

import asyncio
import atexit
import hashlib
import logging
import os
import re
import signal
import subprocess
import threading
import time
import weakref

log = logging.getLogger(__name__)


BASE_CIDR = 20  # networks: 10.200.<n>.0/30 for pool member n
_NETNS_BASE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_IFNAMSIZ = 15
_ACTIVE_POOLS: weakref.WeakSet[NetNsPool] = weakref.WeakSet()
_CLEANUP_HOOKS_INSTALLED = False


class NetNsPool:
    def __init__(self, size: int = 4, base: str = "bs-p"):
        if not _NETNS_BASE_RE.match(base):
            raise ValueError(f"invalid netns base {base!r}: must match ^[A-Za-z0-9_-]+$")
        self.size = size
        self.base = base
        self._queue: asyncio.Queue | None = None
        self._created = False
        self._names: list[str] = []
        self._iface: str = ""  # cached interface name
        self._lock = threading.Lock()
        _ACTIVE_POOLS.add(self)

    @staticmethod
    def _veth_names(name: str) -> tuple[str, str]:
        """Deterministic veth pair names (IFNAMSIZ=15) with stable vh-/vn- prefix.

        A blind ``f"vh-{name}"[-15:]`` drops the ``vh-`` prefix on long names,
        so leftover interfaces no longer match ``_get_iface()``'s skip rules.
        """
        digest = hashlib.blake2s(name.encode(), digest_size=4).hexdigest()
        host = f"vh-{digest}"
        peer = f"vn-{digest}"
        if len(host) > _IFNAMSIZ or len(peer) > _IFNAMSIZ:
            raise ValueError(f"veth name too long for {name!r}")
        return host, peer

    @staticmethod
    def _nat_subnet(idx: int) -> str:
        """Network CIDR for iptables -s (kernel stores .0/30, not host .1/30)."""
        subnet = BASE_CIDR + idx
        return f"10.200.{subnet}.0/30"

    @staticmethod
    def _dns_nameserver() -> str:
        from blockchecks.engine.config import first_udp_nameserver

        return first_udp_nameserver()

    @classmethod
    def _install_cleanup_hooks(cls) -> None:
        global _CLEANUP_HOOKS_INSTALLED
        if _CLEANUP_HOOKS_INSTALLED:
            return
        _CLEANUP_HOOKS_INSTALLED = True
        atexit.register(cls._destroy_active_pools)

        def _on_signal(signum: int, _frame) -> None:
            cls._destroy_active_pools()
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, _on_signal)
            except (ValueError, OSError):
                pass

    @classmethod
    def _destroy_active_pools(cls) -> None:
        for pool in list(_ACTIVE_POOLS):
            try:
                pool.destroy_all()
            except Exception:
                pass

    def _ensure_queue(self) -> asyncio.Queue:
        if self._queue is None:
            self._queue = asyncio.Queue(self.size)
        return self._queue

    def _run(self, *args, check: bool = True) -> subprocess.CompletedProcess:
        """Run a command with sudo, optionally checking for errors.

        A hung netns (uninterruptible D-state) makes ``ip netns exec/delete``
        block forever in the kernel. The 15s wall timeout bounds every command;
        on timeout we return a synthetic failure instead of raising, so cleanup
        never deadlocks the event loop / worker thread.
        """
        try:
            r = subprocess.run(["sudo"] + list(args), capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired:
            r = subprocess.CompletedProcess(
                args=list(args),
                returncode=-1,
                stdout="",
                stderr=f"timeout after 15s: {' '.join(args)}",
            )
        if check and r.returncode != 0:
            raise RuntimeError(f"cmd failed: {' '.join(args)} → {(r.stderr or '')[:200]!r}")
        return r

    def _get_iface(self) -> str:
        """Find a working non-loopback interface (cached).

        Excludes veth/peer interfaces (``veth*``, ``vh-*``, ``vn-*`` or names
        with an ``@`` peer suffix) — otherwise a leftover UP veth from a prior
        pool (or a concurrently running bs) is picked as the out-interface and
        ``iptables -o vh-...@ifNNN`` fails with "interface name must be shorter
        than IFNAMSIZ (15)".
        """
        if self._iface:
            return self._iface
        r = subprocess.run(["ip", "-br", "link", "show"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2 or parts[1] != "UP" or parts[0] == "lo":
                continue
            name = parts[0]
            if "@" in name or name.startswith(("veth", "vh-", "vn-")):
                continue
            self._iface = name
            return self._iface
        self._iface = "eth0"
        return self._iface

    def _create_one(self, idx: int) -> str:
        """Create one netns + veth pair. Returns ns name."""
        name = f"{self.base}-{idx}"
        subnet = BASE_CIDR + idx
        host_ip = f"10.200.{subnet}.1"
        ns_ip = f"10.200.{subnet}.2"
        veth_h, veth_n = self._veth_names(name)
        out_iface = self._get_iface()
        cidr_mask = 30
        nat_subnet = self._nat_subnet(idx)

        # Cleanup any leftovers from previous runs
        self._run("ip", "netns", "delete", name, check=False)
        self._run("ip", "link", "delete", veth_h, check=False)
        # Clean up any stale host interface holding host_ip from a prior aborted PID
        try:
            r = subprocess.run(
                ["ip", "-o", "-4", "addr", "show", "to", host_ip],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    old_iface = parts[1]
                    if old_iface.startswith(("vh-", "vn-", "veth")):
                        self._run("ip", "link", "delete", old_iface, check=False)
        except Exception:
            pass
        time.sleep(0.1)

        # Create
        self._run("ip", "netns", "add", name)
        self._run("ip", "link", "add", veth_h, "type", "veth", "peer", "name", veth_n)
        self._run("ip", "link", "set", veth_n, "netns", name)

        # IP addresses
        self._run("ip", "addr", "add", f"{host_ip}/{cidr_mask}", "dev", veth_h)
        self._run("ip", "link", "set", veth_h, "up")
        self._run(
            "ip", "netns", "exec", name, "ip", "addr", "add", f"{ns_ip}/{cidr_mask}", "dev", veth_n
        )
        self._run("ip", "netns", "exec", name, "ip", "link", "set", veth_n, "up")
        self._run("ip", "netns", "exec", name, "ip", "link", "set", "lo", "up")

        # Routing
        self._run("ip", "netns", "exec", name, "ip", "route", "add", "default", "via", host_ip)

        # Enable forwarding
        self._run("sysctl", "-w", "net.ipv4.ip_forward=1", check=False)
        # Allow forwarded traffic from veth pairs
        self._run("iptables", "-A", "FORWARD", "-i", veth_h, "-j", "ACCEPT", check=False)
        self._run("iptables", "-A", "FORWARD", "-o", veth_h, "-j", "ACCEPT", check=False)
        # Idempotent NAT: -C first so a SIGKILLed previous run's orphan rule is
        # reused instead of duplicated (leaked rules piled up 60+ across runs).
        nat_args = (
            "-s",
            nat_subnet,
            "-o",
            out_iface,
            "-j",
            "MASQUERADE",
        )
        chk = self._run("iptables", "-t", "nat", "-C", "POSTROUTING", *nat_args, check=False)
        if chk.returncode != 0:
            self._run(
                "iptables",
                "-t",
                "nat",
                "-I",
                "POSTROUTING",
                "1",
                *nat_args,
            )

        # DNS — argv-only write (no bash -c)
        dns_dir = f"/etc/netns/{name}"
        self._run("mkdir", "-p", dns_dir)
        resolv = f"{dns_dir}/resolv.conf"
        r = subprocess.run(
            ["sudo", "tee", resolv],
            input=f"nameserver {self._dns_nameserver()}\n",
            capture_output=True,
            text=True,
            timeout=15,
        )
        if r.returncode != 0:
            raise RuntimeError(f"tee resolv.conf failed: {r.stderr[:200]}")

        self._names.append(name)
        return name

    def _destroy_one(self, name: str) -> None:
        """Destroy one netns."""
        idx = int(name.rsplit("-", 1)[-1]) if "-" in name else 0
        veth_h, _veth_n = self._veth_names(name)
        out_iface = self._get_iface()
        nat_subnet = self._nat_subnet(idx)

        # Scoped kill (host-wide pkill via netns exec is forbidden — see
        # metrics.pkill_nfqws2_in_ns).
        from blockchecks.service.metrics import pkill_nfqws2_in_ns

        pkill_nfqws2_in_ns(name)
        self._run("ip", "netns", "exec", name, "iptables", "-F", "OUTPUT", check=False)
        self._run("ip", "netns", "delete", name, check=False)
        self._run("ip", "link", "delete", veth_h, check=False)
        self._run("iptables", "-D", "FORWARD", "-i", veth_h, "-j", "ACCEPT", check=False)
        self._run("iptables", "-D", "FORWARD", "-o", veth_h, "-j", "ACCEPT", check=False)
        self._run(
            "iptables",
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            nat_subnet,
            "-o",
            out_iface,
            "-j",
            "MASQUERADE",
            check=False,
        )
        dns_dir = f"/etc/netns/{name}"
        self._run("rm", "-rf", dns_dir, check=False)

    def _cleanup_ns(self, ns_name: str) -> None:
        """Best-effort cleanup inside a netns before returning to pool."""
        from blockchecks.service.lua_bridge_ipc import LuaBridge
        from blockchecks.service.metrics import pkill_nfqws2_in_ns

        pkill_nfqws2_in_ns(ns_name)
        LuaBridge(ns_name).teardown()
        self._run("ip", "netns", "exec", ns_name, "iptables", "-F", "OUTPUT", check=False)

    # Public API

    def create_all(self) -> None:
        """Synchronous — create namespaces only (no Queue mutations)."""
        self._install_cleanup_hooks()
        with self._lock:
            if self._created:
                return
            created: list[str] = []
            try:
                for i in range(self.size):
                    created.append(self._create_one(i))
                self._created = True
            except Exception:
                for name in created:
                    try:
                        self._destroy_one(name)
                    except Exception:
                        pass
                self._names.clear()
                raise
        log.info("%s", f"[netns] Pool created: {self.size} namespaces")

    async def seed(self) -> None:
        """Put created ns names onto the asyncio.Queue (event-loop only)."""
        q = self._ensure_queue()
        for name in self._names:
            await q.put(name)

    async def drain(self) -> None:
        """Empty the queue on the event loop before destroy_all()."""
        if self._queue is None:
            return
        while True:
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break

    def destroy_all(self) -> None:
        """Synchronous — destroy namespaces. Call drain() on loop first."""
        with self._lock:
            if not self._created and not self._names:
                return
            self._created = False
            names_to_destroy = list(self._names)
            self._names.clear()
        for name in names_to_destroy:
            self._destroy_one(name)
        if names_to_destroy:
            log.info("[netns] Pool destroyed")

    async def acquire(self) -> str:
        """Get a free netns from the pool. Blocks if all busy."""
        return await self._ensure_queue().get()

    async def release(self, ns_name: str) -> None:
        """Return ns to pool after cleaning it up. Always re-queues."""
        try:
            await asyncio.to_thread(self._cleanup_ns, ns_name)
        finally:
            await self._ensure_queue().put(ns_name)
