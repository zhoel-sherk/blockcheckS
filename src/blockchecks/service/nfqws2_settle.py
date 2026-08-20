"""Wait until nfqws2 is ready after start."""

from __future__ import annotations

import time

from blockchecks.engine.config import (
    NFQWS2_SETTLE_MAX,
    NFQWS2_SETTLE_MIN,
    NFQWS2_SETTLE_POLL,
)


def nfqws2_count_in_ns(ns_name: str) -> int:
    """How many nfqws2 processes are running inside *ns_name*.

    Uses stdlib ``/proc`` inode matching (``metrics.find_nfqws2_pids``) instead
    of ``ip netns exec pgrep``, which scans the host ``/proc`` and causes
    cross-worker settle timeout loops in multi-worker pools.
    """
    from blockchecks.service.metrics import find_nfqws2_pids

    try:
        return len(find_nfqws2_pids(ns_name))
    except OSError:
        return 0


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
