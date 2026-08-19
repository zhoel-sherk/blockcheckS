"""Memory monitor — nfqws2 daemon + Python worker RSS tracking and leak guard.

Samples RSS/VMS of nfqws2 daemons inside netns and the Python worker, keeps a
sliding window per daemon, and estimates a leak slope via linear regression.
When a daemon exceeds the RSS ceiling or leak slope it is flagged for recycle
(the caller rebuilds the bridge via ``BridgeSession.boot()``).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from blockchecks.engine.config import (
    MEM_MONITOR_ENABLED,
    MEM_MONITOR_LEAK_SLOPE,
    MEM_MONITOR_MAX_MIB,
    MEM_MONITOR_POLL,
    MEM_MONITOR_PY_MAX_MIB,
    MEM_MONITOR_WINDOW,
)

MIB = 1024 * 1024


@dataclass(frozen=True)
class MemorySample:
    """One RSS observation of a daemon process."""

    ts: float
    rss_bytes: int

    @property
    def rss_mib(self) -> float:
        return self.rss_bytes / MIB


@dataclass
class _Window:
    samples: list[MemorySample] = field(default_factory=list)

    def push(self, s: MemorySample, window: int) -> None:
        self.samples.append(s)
        if len(self.samples) > max(1, int(window)):
            del self.samples[: len(self.samples) - int(window)]

    def clear(self) -> None:
        self.samples.clear()


def _proc_status_value(pid: int, field: str) -> int:
    """Parse ``/proc/<pid>/status`` field (e.g. VmRSS) → bytes, 0 on any error.

    Value is printed in kB; multiplied by 1024. Handles process races
    (process may exit mid-read) and permission errors gracefully.
    """
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith(f"{field}:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].strip().isdigit():
                        return int(parts[1]) * 1024
                    return 0
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        return 0
    return 0


def process_rss_bytes(pid: int) -> int:
    """RSS in bytes for *pid* (0 on any error). Stdlib /proc reader (no psutil)."""
    return _proc_status_value(pid, "VmRSS")


def process_vms_bytes(pid: int) -> int:
    """VMS in bytes for *pid* (0 on any error). Stdlib /proc reader (no psutil)."""
    return _proc_status_value(pid, "VmSize")


def find_nfqws2_pids(ns_name: str) -> list[int]:
    """PID list of nfqws2 running inside *ns_name* (stdlib /proc, no subprocess).

    Matches the netns inode of each nfqws2 process against the bind-mounted
    namespace file under ``/var/run/netns/<name>``.  Avoids ``sudo ip netns
    exec pgrep`` in the hot probe loop, which stalls under parallel bridge
    workers (blocking subprocess + race on shared state).

    Handles process races (a process may exit while we iterate /proc): every
    /proc access is guarded against FileNotFoundError / ProcessLookupError /
    PermissionError / OSError.
    """
    try:
        ns_file = f"/var/run/netns/{ns_name}"
        ns_inode = os.stat(ns_file).st_ino
    except OSError:
        return []
    pids: list[int] = []
    try:
        proc_dirs = os.listdir("/proc")
    except OSError:
        return []
    for entry in proc_dirs:
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            # Only consider nfqws2-named processes (cheap comm read first).
            try:
                with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as cf:
                    comm = cf.read().strip()
            except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
                continue
            if comm != "nfqws2":
                continue
            link = os.readlink(f"/proc/{pid}/ns/net")
            if link.endswith(f"[{ns_inode}]"):
                pids.append(pid)
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            continue
    return pids


def compute_leak_slope(samples: list[MemorySample]) -> float:
    """Linear-regression slope of RSS vs time in MiB/s (0 if <2 samples)."""
    if len(samples) < 2:
        return 0.0
    xs = [s.ts for s in samples]
    ys = [s.rss_bytes / MIB for s in samples]
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
    den = sum((x - mean_x) ** 2 for x in xs)
    if den == 0:
        return 0.0
    return num / den


class MemoryMonitor:
    """Sliding-window RSS tracker with leak detection for daemons + worker.

    Not thread-safe: call from a single task / between awaits only.
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        max_mib: float | None = None,
        leak_slope: float | None = None,
        py_max_mib: float | None = None,
        window: int | None = None,
        poll: float | None = None,
    ) -> None:
        self.enabled = enabled and MEM_MONITOR_ENABLED
        self.max_mib = MEM_MONITOR_MAX_MIB if max_mib is None else float(max_mib)
        self.leak_slope = MEM_MONITOR_LEAK_SLOPE if leak_slope is None else float(leak_slope)
        self.py_max_mib = MEM_MONITOR_PY_MAX_MIB if py_max_mib is None else float(py_max_mib)
        self.window = MEM_MONITOR_WINDOW if window is None else int(window)
        self.poll = MEM_MONITOR_POLL if poll is None else float(poll)
        self._windows: dict[int, _Window] = {}
        self._last_py_sample: MemorySample | None = None
        self._last_check = float("-inf")

    def should_sample(self) -> bool:
        """Rate-limit sampling to every ``poll`` seconds."""
        if not self.enabled:
            return False
        now = time.monotonic()
        if now - self._last_check < self.poll:
            return False
        self._last_check = now
        return True

    def clear(self, pid: int | None = None) -> None:
        """Drop tracked windows (after a daemon recycle)."""
        if pid is None:
            self._windows.clear()
            return
        self._windows.pop(pid, None)

    def record_pid(self, pid: int) -> None:
        """Sample one daemon PID; called between probes / after settle."""
        if not self.enabled:
            return
        rss = process_rss_bytes(pid)
        if rss <= 0:
            return
        w = self._windows.setdefault(pid, _Window())
        w.push(MemorySample(time.monotonic(), rss), self.window)

    def record_ns(self, ns_name: str, pids: list[int] | None = None) -> None:
        """Sample all nfqws2 daemons in *ns_name* (default: discover via pgrep)."""
        if not self.enabled:
            return
        for pid in pids if pids is not None else find_nfqws2_pids(ns_name):
            self.record_pid(pid)

    def sample_worker(self) -> MemorySample | None:
        """Sample the Python worker (this process) RSS."""
        rss = process_rss_bytes(os.getpid())
        if rss <= 0:
            return None
        s = MemorySample(time.monotonic(), rss)
        self._last_py_sample = s
        return s

    def worker_over_limit(self) -> bool:
        self.sample_worker()
        if self._last_py_sample is None:
            return False
        return self._last_py_sample.rss_mib > self.py_max_mib

    def recycle_candidates(self) -> list[tuple[int, str]]:
        """Return ``(pid, reason)`` for daemons exceeding RSS ceiling or leak slope."""
        out: list[tuple[int, str]] = []
        for pid, w in self._windows.items():
            if not w.samples:
                continue
            last = w.samples[-1]
            if last.rss_mib > self.max_mib:
                out.append((pid, f"rss={last.rss_mib:.0f}MiB > {self.max_mib:.0f}MiB"))
                continue
            slope = compute_leak_slope(w.samples)
            if slope > self.leak_slope:
                out.append((pid, f"leak={slope:.1f}MiB/s > {self.leak_slope:.1f}MiB/s"))
        return out

    def summary(self) -> dict:
        """Current tracked state (for logs / tests)."""
        return {
            "enabled": self.enabled,
            "windows": {str(k): len(w.samples) for k, w in self._windows.items()},
            "worker_rss_mib": (self._last_py_sample.rss_mib if self._last_py_sample else None),
        }
