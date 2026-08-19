"""nfqws2 post-start settle / readiness poll (Phase 11 B1)."""

from __future__ import annotations

import subprocess as sp
import time

from blockchecks.engine.config import (
    NFQWS2_SETTLE_MAX,
    NFQWS2_SETTLE_MIN,
    NFQWS2_SETTLE_POLL,
)


def nfqws2_count_in_ns(ns_name: str) -> int:
    """How many nfqws2 processes are visible inside the netns."""
    try:
        r = sp.run(
            ["sudo", "ip", "netns", "exec", ns_name, "pgrep", "-x", "nfqws2"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (sp.TimeoutExpired, OSError):
        return 0
    if r.returncode != 0:
        return 0
    return sum(1 for ln in r.stdout.splitlines() if ln.strip())


def nfqws2_running_in_ns(ns_name: str) -> bool:
    """True when nfqws2 process is visible inside the netns."""
    return nfqws2_count_in_ns(ns_name) >= 1


def wait_nfqws2_ready(
    ns_name: str,
    *,
    max_wait: float | None = None,
    poll_interval: float | None = None,
    min_wait: float | None = None,
    min_procs: int = 1,
) -> float:
    """Poll until nfqws2 is running in netns (or max_wait elapsed).

    ``min_procs`` > 1 waits for coexist (TCP+UDP) daemons. Returns elapsed seconds.
    """
    settle_max = NFQWS2_SETTLE_MAX if max_wait is None else max_wait
    settle_poll = NFQWS2_SETTLE_POLL if poll_interval is None else poll_interval
    settle_min = NFQWS2_SETTLE_MIN if min_wait is None else min_wait
    need = max(1, min_procs)

    start = time.perf_counter()
    if settle_min > 0:
        time.sleep(settle_min)
    deadline = start + max(settle_max, settle_min)
    while time.perf_counter() < deadline:
        ready = nfqws2_running_in_ns(ns_name) if need <= 1 else nfqws2_count_in_ns(ns_name) >= need
        if ready:
            return time.perf_counter() - start
        if settle_poll > 0:
            time.sleep(settle_poll)
    return time.perf_counter() - start


def _wait_nfqws2_gone(ns_name: str, *, max_wait: float = 2.0, poll_interval: float = 0.05) -> bool:
    """Poll until nfqws2 is gone from the netns (post-pkill drain).

    pkill(9) is asynchronous — the dying daemon can hold the NFQUEUE socket for
    a few ms. If we bind a replacement too early it dies with a queue conflict
    (settle spikes + "PASS without APPLIED"). Returns True when gone/never was
    there, False on timeout.
    """
    start = time.perf_counter()
    deadline = start + max(0.0, max_wait)
    while time.perf_counter() < deadline:
        if not nfqws2_running_in_ns(ns_name):
            return True
        if poll_interval > 0:
            time.sleep(poll_interval)
    return not nfqws2_running_in_ns(ns_name)
