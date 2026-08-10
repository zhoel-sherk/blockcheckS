"""Network namespace pool for async parallel testing.

Fixed-size pool of pre-created netns. Workers acquire/release instead of
create/destroy per test — avoids kernel race conditions on veth creation.

Thread safety: create_all() and destroy_all() are synchronous (called via
asyncio.to_thread). Queue mutations (seed/drain/acquire/release) run only
on the event loop thread.
"""

import asyncio
import re
import subprocess
import threading
import time

BASE_CIDR = 20  # networks: 10.200.<n>.0/30 for pool member n
_NETNS_BASE_RE = re.compile(r"^[A-Za-z0-9_-]+$")


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

    def _ensure_queue(self) -> asyncio.Queue:
        if self._queue is None:
            self._queue = asyncio.Queue(self.size)
        return self._queue

    def _run(self, *args, check: bool = True) -> subprocess.CompletedProcess:
        """Run a command with sudo, optionally checking for errors."""
        r = subprocess.run(["sudo"] + list(args), capture_output=True, text=True, timeout=15)
        if check and r.returncode != 0:
            raise RuntimeError(f"cmd failed: {' '.join(args)} → {r.stderr[:200]}")
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
        veth_h = f"vh-{name}"[-15:]
        veth_n = f"vn-{name}"[-15:]
        out_iface = self._get_iface()
        cidr_mask = 30

        # Cleanup any leftovers from previous runs
        self._run("ip", "netns", "delete", name, check=False)
        self._run("ip", "link", "delete", veth_h, check=False)
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
        self._run(
            "iptables",
            "-t",
            "nat",
            "-I",
            "POSTROUTING",
            "1",
            "-s",
            f"{host_ip}/{cidr_mask}",
            "-o",
            out_iface,
            "-j",
            "MASQUERADE",
        )

        # DNS — argv-only write (no bash -c)
        dns_dir = f"/etc/netns/{name}"
        self._run("mkdir", "-p", dns_dir)
        resolv = f"{dns_dir}/resolv.conf"
        r = subprocess.run(
            ["sudo", "tee", resolv],
            input="nameserver 8.8.8.8\n",
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
        subnet = BASE_CIDR + idx
        host_ip = f"10.200.{subnet}.1"
        veth_h = f"vh-{name}"[-15:]
        out_iface = self._get_iface()
        cidr_mask = 30

        self._run("ip", "netns", "exec", name, "pkill", "-9", "nfqws2", check=False)
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
            f"{host_ip}/{cidr_mask}",
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

        LuaBridge(ns_name).teardown()
        self._run("ip", "netns", "exec", ns_name, "pkill", "-9", "nfqws2", check=False)
        self._run("ip", "netns", "exec", ns_name, "iptables", "-F", "OUTPUT", check=False)

    # ── Public API ──

    def create_all(self) -> None:
        """Synchronous — create namespaces only (no Queue mutations)."""
        with self._lock:
            if self._created:
                return
            for i in range(self.size):
                self._create_one(i)
            self._created = True
        print(f"[netns] Pool created: {self.size} namespaces")

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
            if not self._created:
                return
            self._created = False
        names_to_destroy = list(self._names)
        for name in names_to_destroy:
            self._destroy_one(name)
        self._names.clear()
        print("[netns] Pool destroyed")

    async def acquire(self) -> str:
        """Get a free netns from the pool. Blocks if all busy."""
        return await self._ensure_queue().get()

    async def release(self, ns_name: str) -> None:
        """Return ns to pool after cleaning it up. Always re-queues."""
        try:
            await asyncio.to_thread(self._cleanup_ns, ns_name)
        finally:
            await self._ensure_queue().put(ns_name)
