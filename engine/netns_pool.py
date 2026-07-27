"""Network namespace pool for async parallel testing.

Fixed-size pool of pre-created netns. Workers acquire/release ns instead of
create/destroy per test — avoids kernel race conditions on veth creation.

Lifecycle:
  1. create_all() — create N veth pairs + netns + MASQUERADE
  2. acquire() / release() — get/return ns via asyncio.Queue
  3. destroy_all() — clean shutdown; also registered as atexit + SIGINT handler

Between tests: release() flushes iptables + kills stale nfqws2 inside the ns.
"""

import asyncio
import os
import subprocess
import time
from typing import Optional

BASE_CIDR = 20  # networks: 10.200.<n>.0/30 for pool member n


class NetNsPool:
    """Pre-created network namespace pool."""

    def __init__(self, size: int = 4, base: str = "bs-p"):
        self.size = size
        self.base = base
        self._queue: asyncio.Queue[str] = asyncio.Queue(size)
        self._created = False
        self._names: list[str] = []

    def _run(self, *args, check: bool = True) -> subprocess.CompletedProcess:
        """Run a command with sudo, optionally checking for errors."""
        r = subprocess.run(["sudo"] + list(args), capture_output=True,
                          text=True, timeout=15)
        if check and r.returncode != 0:
            raise RuntimeError(f"cmd failed: {' '.join(args)} → {r.stderr[:200]}")
        return r

    def _get_iface(self) -> str:
        """Find a working non-loopback interface."""
        r = subprocess.run(["ip", "-br", "link", "show"], capture_output=True,
                          text=True)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "UP" and parts[0] != "lo":
                return parts[0]
        return "eth0"

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
        self._run("ip", "link", "add", veth_h, "type", "veth",
                  "peer", "name", veth_n)
        self._run("ip", "link", "set", veth_n, "netns", name)

        # IP addresses
        self._run("ip", "addr", "add", f"{host_ip}/{cidr_mask}",
                  "dev", veth_h)
        self._run("ip", "link", "set", veth_h, "up")
        self._run("ip", "netns", "exec", name, "ip", "addr", "add",
                  f"{ns_ip}/{cidr_mask}", "dev", veth_n)
        self._run("ip", "netns", "exec", name, "ip", "link", "set",
                  veth_n, "up")
        self._run("ip", "netns", "exec", name, "ip", "link", "set",
                  "lo", "up")

        # Routing
        self._run("ip", "netns", "exec", name, "ip", "route", "add",
                  "default", "via", host_ip)

        # Enable forwarding
        self._run("sysctl", "-w", "net.ipv4.ip_forward=1", check=False)
        self._run("iptables", "-t", "nat", "-I", "POSTROUTING", "1",
                  "-s", f"{host_ip}/{cidr_mask}", "-o", out_iface,
                  "-j", "MASQUERADE")

        # DNS
        dns_dir = f"/etc/netns/{name}"
        self._run("mkdir", "-p", dns_dir)
        self._run("bash", "-c",
                  f"echo 'nameserver 8.8.8.8' > {dns_dir}/resolv.conf")

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

        self._run("ip", "netns", "exec", name, "pkill", "-9", "nfqws2",
                  check=False)
        self._run("ip", "netns", "exec", name, "iptables", "-F", "OUTPUT",
                  check=False)
        self._run("ip", "netns", "delete", name, check=False)
        self._run("ip", "link", "delete", veth_h, check=False)
        self._run("iptables", "-t", "nat", "-D", "POSTROUTING",
                  "-s", f"{host_ip}/{cidr_mask}", "-o", out_iface,
                  "-j", "MASQUERADE", check=False)
        dns_dir = f"/etc/netns/{name}"
        self._run("rm", "-rf", dns_dir, check=False)

    # ── Public API ──

    def create_all(self) -> None:
        """Synchronous — call once at startup via asyncio.to_thread()."""
        if self._created:
            return
        for i in range(self.size):
            name = self._create_one(i)
            self._queue.put_nowait(name)
        self._created = True
        print(f"[netns] Pool created: {self.size} namespaces")

    def destroy_all(self) -> None:
        """Synchronous — call at shutdown or SIGINT."""
        if not self._created:
            return
        while not self._queue.empty():
            try:
                name = self._queue.get_nowait()
                self._destroy_one(name)
            except asyncio.QueueEmpty:
                break
        for name in self._names:
            self._destroy_one(name)
        self._names.clear()
        self._created = False
        print(f"[netns] Pool destroyed")

    async def acquire(self) -> str:
        """Get a free netns from the pool. Blocks if all busy."""
        return await self._queue.get()

    async def release(self, ns_name: str) -> None:
        """Return ns to pool after cleaning it up."""
        self._run("ip", "netns", "exec", ns_name,
                  "pkill", "-9", "nfqws2", check=False)
        self._run("ip", "netns", "exec", ns_name,
                  "iptables", "-F", "OUTPUT", check=False)
        await self._queue.put(ns_name)
