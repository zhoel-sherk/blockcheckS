"""Wait until nfqws2 is ready after start."""

from __future__ import annotations

import time
from pathlib import Path

from blockchecks.engine.config import (
    NFQWS2_SETTLE_MAX,
    NFQWS2_SETTLE_MIN,
    NFQWS2_SETTLE_POLL,
)

#: nfqws2 prints this after NFQUEUE bind succeeds (stdout, not --debug).
NFQWS2_BIND_MARKER = "setting copy_packet mode"

#: Same window as batch_service._wait_heartbeat (zero-events reboot backstop).
NFQWS2_BIND_PROOF_WAIT = 1.2


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


def nfqws2_pid_in_ns(pid: int, ns_name: str) -> bool:
    """True when *pid* is an nfqws2 process inside *ns_name*."""
    return pid in resolve_nfqws2_pids(ns_name)


def resolve_nfqws2_pids(
    ns_name: str, baseline: set[int] | frozenset[int] | None = None
) -> list[int]:
    """Real nfqws2 PIDs in *ns_name* (``comm==nfqws2``), minus *baseline*.

    The sudo / ``ip netns exec`` wrapper PID is never in this list. For
    coexist launches (``kill_existing=False``) pass the pre-launch snapshot.
    """
    from blockchecks.service.metrics import find_nfqws2_pids

    try:
        found = find_nfqws2_pids(ns_name)
    except OSError:
        return []
    return found if baseline is None else [p for p in found if p not in baseline]


def nfqws2_out_shows_bind(out_path: Path | str | None) -> bool:
    """True when stdout capture shows NFQUEUE bind (conf was read and applied)."""
    if out_path is None:
        return False
    try:
        text = Path(out_path).read_text(errors="replace")[:4000]
    except OSError:
        return False
    return NFQWS2_BIND_MARKER in text


def nfqws2_out_shows_bind_busy(out_txt: str) -> bool:
    """True when stdout capture shows NFQUEUE bind conflict (retryable, zapret2#300)."""
    return "Operation not permitted" in out_txt and "nfq_create_queue" in out_txt


def nfqws2_bind_retry_backoff(attempt: int) -> float:
    """Seconds to wait before the next bind attempt (linear cap at 6s)."""
    return min(2.0 * attempt, 6.0)


def nfqws2_bind_retry_should_continue(
    out_txt: str,
    *,
    attempt: int,
    max_attempts: int,
    drain_ok: bool = True,
    succeeded: bool = False,
) -> tuple[bool, str | None]:
    """Whether to retry nfqws2 launch after a failed bind.

    Retry only for NFQUEUE bind conflicts (``nfq_create_queue(): Operation not
    permitted``) or incomplete pkill drain — not for SSL/config parse failures.

    Returns ``(should_retry, reason)`` where *reason* is suitable for log.warning.
    """
    if succeeded or attempt >= max_attempts:
        return False, None
    if nfqws2_out_shows_bind_busy(out_txt):
        return True, "queue busy"
    if not drain_ok:
        return True, "pkill drain incomplete"
    return False, None


def wait_nfqws2_bind_proof(
    ns_name: str,
    *,
    baseline_pids: set[int] | frozenset[int] | None = None,
    out_path: Path | str | None = None,
    within: float = NFQWS2_BIND_PROOF_WAIT,
) -> bool:
    """Block until bind marker or a real nfqws2 pid appears in the ns.

    Bind marker (``setting copy_packet mode``) is primary. PID proof uses
    ``find_nfqws2_pids`` (comm==nfqws2), never the sudo wrapper PID.
    *baseline_pids* is the pre-launch snapshot for coexist.
    """

    def _proved() -> bool:
        return nfqws2_out_shows_bind(out_path) or bool(resolve_nfqws2_pids(ns_name, baseline_pids))

    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if _proved():
            return True
        if within > 0:
            time.sleep(0.05)
    return _proved()


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


def _nfqws2_scan(ns_name: str) -> tuple[int, int]:
    """Return ``(pid_count, scan_errors)``; ``(0, 0)`` on unexpected OSError."""
    from blockchecks.service.metrics import _find_nfqws2_pids

    try:
        pids, scan_errors = _find_nfqws2_pids(ns_name)
    except OSError:
        return 0, 0
    return len(pids), scan_errors


def _wait_nfqws2_gone(ns_name: str, *, max_wait: float = 2.0, poll_interval: float = 0.05) -> bool:
    """Poll until nfqws2 is gone from the netns (post-pkill drain).

    pkill(9) is asynchronous — the dying daemon can hold the NFQUEUE socket for
    a few ms. If we bind a replacement too early it dies with a queue conflict
    (settle spikes + "PASS without APPLIED"). Returns True when gone/never was
    there, False on timeout **or** when the /proc scan is EPERM-unknown
    (empty PID list with scan_errors — do not treat as drain_ok).
    """
    start = time.perf_counter()
    deadline = start + max(0.0, max_wait)
    while time.perf_counter() < deadline:
        count, scan_errors = _nfqws2_scan(ns_name)
        if count == 0 and scan_errors == 0:
            return True
        if poll_interval > 0:
            time.sleep(poll_interval)
    count, scan_errors = _nfqws2_scan(ns_name)
    return count == 0 and scan_errors == 0
