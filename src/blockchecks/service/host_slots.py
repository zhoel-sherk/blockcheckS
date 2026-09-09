"""Host-mode slot pool (v2) — docs/hostmode.md §10/§9.

Same ``acquire``/``release``/``create_all``/``destroy_all``/``seed``/``drain``
contract as :class:`NetNsPool`, but zero netns: slot *i* owns qnum
``HOST_QNUM_TCP + 2*i`` (UDP later 221+2*i, canon §6), a shm dir
``/dev/shm/blockchecks/host-q<qnum>-<pid>/`` and one foreground nfqws2.
Slot names follow the canon ``host-q<N>-<pid>`` shape — never a bare
``"host"`` (probe.py would netns-exec it).

Hard refusals (canon §18.1 — no silent fallback): missing nft, missing
probe uid, a qnum already owned by ANY other table (``qnum_busy`` scans
the whole ruleset in both nft renderings), missing nft binary.
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import os
import signal
import threading

from blockchecks.engine.config import (
    DESYNC_MARK,
    HOST_PROBE_USER,
    HOST_QNUM_TCP,
    PROBE_MARK,
)

log = logging.getLogger("blockchecks.host_slots")

#: Canon §6: TCP slots take even qnums starting at HOST_QNUM_TCP (220, 222, …);
#: odd qnums are reserved for UDP host slots (221+2*i, v2 UDP wiring).
SLOT_QNUM_STEP = 2


def slot_name(qnum: int) -> str:
    """Canonical host slot name — shm dir + daemon lifetime unit (canon §9)."""
    from blockchecks.engine.config import host_slot_name

    return host_slot_name(qnum)


class HostSlotPool:
    """K host slots = K qnums = K nfqws2 = K LuaBridge shm dirs, no netns."""

    def __init__(
        self,
        size: int = 1,
        base_qnum: int = HOST_QNUM_TCP,
        *,
        skuid: str = HOST_PROBE_USER,
        desync_mark: int = DESYNC_MARK,
        probe_mark: int = PROBE_MARK,
    ) -> None:
        self.size = max(1, int(size))
        self.base_qnum = int(base_qnum)
        self.skuid = skuid
        self.desync_mark = int(desync_mark)
        self.probe_mark = int(probe_mark)
        self._names: list[str] = []
        self._queue: asyncio.Queue | None = None
        self._created = False
        self._lock = threading.Lock()
        self._atexit_registered = False

    # ------------------------------------------------------------------ names
    def _qnums(self) -> list[int]:
        return [self.base_qnum + i * SLOT_QNUM_STEP for i in range(self.size)]

    # ------------------------------------------------------------- validation
    def validate(self) -> None:
        """Pre-flight hard guards. Raises RuntimeError — caller prints/exits."""
        from blockchecks.service.host_isol import nft_available, qnum_busy

        if not nft_available():
            raise RuntimeError("probe-isol=host requires nft; not found in PATH")
        import pwd

        try:
            pwd.getpwnam(self.skuid)
        except KeyError as exc:
            raise RuntimeError(
                f"probe-isol=host requires probe uid {self.skuid!r} (useradd -r); "
                "refusing to queue the whole :443 instead"
            ) from exc
        for qnum in self._qnums():
            owner = qnum_busy(qnum)
            if owner is not None:
                raise RuntimeError(
                    f"host slot qnum {qnum} is already queued by: {owner} — "
                    "refusing (canon §6: no silent rotation, use --host-qnum)"
                )

    @staticmethod
    def _purge_stale_shm(our_pid: int) -> int:
        """Remove host-q* shm dirs whose trailing PID is not alive (canon §9:
        kill -9 leaves dirty strategy.id/events that poison the next boot).
        Foreign LIVE runs (PID alive, different from ours) are left alone."""
        import shutil as _shutil

        from blockchecks.engine.config import SHM_BASE

        purged = 0
        try:
            entries = list(os.scandir(SHM_BASE))
        except OSError:
            return 0
        for entry in entries:
            name = entry.name
            if not name.startswith("host-q") or "-" not in name:
                continue
            tail = name.rsplit("-", 1)[-1]
            if not tail.isdigit():
                continue
            pid = int(tail)
            if pid == our_pid:
                continue
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                try:
                    _shutil.rmtree(entry.path)
                    purged += 1
                except OSError:
                    pass
            except OSError:
                continue  # alive or unreadable — leave it
        return purged

    # ----------------------------------------------------------------- create
    def create_all(self) -> None:
        """Synchronous — validate + register slots only (no queue mutations)."""
        self._register_atexit_hook()
        with self._lock:
            if self._created:
                return
            purged = self._purge_stale_shm(os.getpid())
            if purged:
                log.info("purged %d stale host-q shm dirs (dead PIDs)", purged)
            self.validate()
            self._names = [slot_name(q) for q in self._qnums()]
            self._created = True
            log.info(
                "host slot pool ready: %s (skuid=%s desync=0x%x probe=%s)",
                ",".join(self._names),
                self.skuid,
                self.desync_mark,
                f"0x{self.probe_mark:x}" if self.probe_mark else "off",
            )

    def _register_atexit_hook(self) -> None:
        if self._atexit_registered:
            return
        self._atexit_registered = True
        atexit.register(self.destroy_all)

    def install_signal_hooks(cls) -> None:  # noqa: N805 — parity with NetNsPool
        """SIGTERM/SIGINT-safe teardown without blocking acquire (§12 lesson)."""
        pool = cls

        def _teardown(_sig, _frm):
            pool.destroy_all()
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            os.kill(os.getpid(), signal.SIGTERM)

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, _teardown)
            except (ValueError, OSError):
                pass

    # ------------------------------------------------------------------ queue
    def _ensure_queue(self) -> asyncio.Queue:
        if self._queue is None:
            self._queue = asyncio.Queue()
        return self._queue

    async def seed(self) -> None:
        """Put created slot names onto the asyncio.Queue (event-loop only)."""
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

    async def acquire(self) -> str:
        """Get a free host slot name. Blocks if all busy."""
        return await self._ensure_queue().get()

    async def release(self, _slot_name: str) -> None:
        """Return the slot to the pool. No per-release cleanup: the per-batch
        BridgeSession.shutdown() already killed the slot daemon; workers are
        cached by (slot, python, epoch) and reused."""
        await self._ensure_queue().put(_slot_name)

    # --------------------------------------------------------------- teardown
    def destroy_all(self) -> None:
        """Kill slot daemons (by PID via BridgeSession registry — none left
        between batches), release persistent workers, drop the nft table."""
        with self._lock:
            if not self._created and not self._names:
                return
            self._created = False
            names = list(self._names)
        from blockchecks.service.host_isol import teardown_host_queue
        from blockchecks.service.probe import release_curl_probe_worker

        for name in names:
            try:
                release_curl_probe_worker(name)
            except Exception as exc:  # noqa: BLE001 — best-effort teardown
                log.warning("worker release failed for %s: %s", name, exc)
        try:
            if teardown_host_queue():
                log.info("host nft table deleted (slot pool teardown)")
        except Exception as exc:  # noqa: BLE001 — best-effort teardown
            log.warning("host nft teardown failed: %s", exc)
        self._names = []

    def __repr__(self) -> str:  # pragma: no cover — debug aid
        return f"HostSlotPool(size={self.size}, base_qnum={self.base_qnum}, names={self._names})"


#: Rough per-slot RAM budget (nfqws2 daemon + persistent curl worker + IPC
#: headroom). Conservative on purpose: underestimating starves the host.
PER_SLOT_BUDGET_MIB = 220
#: Absolute ceiling — AQ efficiency flattens well before this on any box.
MAX_SLOTS_CAP = 16


def _mem_available_mib() -> int:
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def resolve_host_slot_count(requested: int | str | None = None) -> int:
    """Slot count for the host pool — AUTO by resource formula, never fixed.

    ``requested``:
      - ``None``            → env ``BLOCKCHECKS_HOST_SLOTS`` else ``auto``;
      - ``"auto"``          → resource formula (below);
      - int (CLI/env)       → operator override, honoured as-is (their box).

    Auto formula: min(cpu-1, 60% of MemAvailable / per-slot budget), clamped
    to [1, MAX_SLOTS_CAP]. Log both branches — no silent substitution (§18.1).
    """
    if requested is None:

        requested = os.environ.get("BLOCKCHECKS_HOST_SLOTS", "auto")
    if isinstance(requested, int) and not isinstance(requested, bool):
        log.info("host slots: operator override = %d", requested)
        return max(1, requested)
    if str(requested).strip().lower() != "auto":
        try:
            n = int(requested)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"BLOCKCHECKS_HOST_SLOTS: expected int or 'auto', got {requested!r}"
            ) from exc
        log.info("host slots: operator override = %d", n)
        return max(1, n)

    cpu_budget = max(1, (os.cpu_count() or 1) - 1)
    mem = _mem_available_mib()
    mem_budget = int(mem * 0.6 / PER_SLOT_BUDGET_MIB) if mem > 0 else cpu_budget
    slots = max(1, min(cpu_budget, mem_budget, MAX_SLOTS_CAP))
    log.info(
        "host slots: auto → %d (cpu_budget=%d, mem=%dMiB → mem_budget=%d, cap=%d)",
        slots,
        cpu_budget,
        mem,
        mem_budget,
        MAX_SLOTS_CAP,
    )
    return slots

__all__ = [
    "HostSlotPool",
    "MAX_SLOTS_CAP",
    "PER_SLOT_BUDGET_MIB",
    "SLOT_QNUM_STEP",
    "resolve_host_slot_count",
    "slot_name",
]
