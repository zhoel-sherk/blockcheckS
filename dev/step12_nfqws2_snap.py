#!/usr/bin/env python3
"""Step 12 sampler (smoke_long): Mode A daemon memory probes (AUDIT §22).

Samples the nfqws2 daemon(s) of a Mode A campaign every ``--interval`` s and
appends to the log:
- RSS total across the daemon set (``/proc/*/comm == nfqws2`` whose cmdline
  carries the temp bridge conf marker) — memory growth / plateau detector;
- ``LUA GARBAGE COLLECT: X K => Y K`` pairs parsed from ``nfqws2_*.log``
  debug files (nfqws2 ``--lua-gc`` cadence, default 60 s) — the direct
  plan-instance leak metric, independent of RSS;
- daemon respawn count (new nfqws2 PID after the initial set → mem-pressure
  reboot / recycle, i.e. a leak signal).
Exits when the daemon set empties after having been seen at least once (the
campaign ended), or on deadline.
"""

import argparse
import glob
import os
import re
import time

_GC_RE = re.compile(r"LUA GARBAGE COLLECT:\s*(\d+)K\s*=>\s*(\d+)K")


def _nfqws2_pids(marker: str) -> tuple[list[int], int]:
    """Return (pids, errors) for nfqws2 comm processes whose cmdline carries
    *marker* (our temp bridge conf). ``/proc`` of the setuid overflow-uid
    daemon is only readable under root — run this sampler via sudo (smoke
    steps run under ``sudo -E bash dev/smoke_long.sh``)."""
    pids: list[int] = []
    errors = 0
    try:
        entries = os.listdir("/proc")
    except OSError:
        return [], 1
    for ent in entries:
        if not ent.isdigit():
            continue
        try:
            with open(f"/proc/{ent}/comm", encoding="utf-8", errors="replace") as f:
                if f.read().strip() != "nfqws2":
                    continue
            with open(f"/proc/{ent}/cmdline", "rb") as f:
                if marker.encode() not in f.read():
                    continue
            pids.append(int(ent))
        except OSError:
            errors += 1
            continue
    return pids, errors


def _rss_kib(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8", errors="replace") as f:
            for ln in f:
                if ln.startswith("VmRSS:"):
                    return int(ln.split()[1])
    except OSError:
        pass
    return 0


def _collect_gc(logdir: str, offsets: dict[str, int]) -> list[tuple[int, int]]:
    """Parse new ``LUA GARBAGE COLLECT`` lines from nfqws2_*.log files.

    ``offsets`` maps file path → last read byte offset; only appended data is
    re-read so a long run does not reparse the whole (possibly huge) log."""
    out: list[tuple[int, int]] = []
    for path in sorted(glob.glob(os.path.join(logdir, "nfqws2_*.log"))):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                off = offsets.get(path, 0)
                if os.path.getsize(path) < off:
                    off = 0  # truncated/rotated
                f.seek(off)
                data = f.read()
                offsets[path] = f.tell()
        except OSError:
            continue
        for m in _GC_RE.finditer(data):
            out.append((int(m.group(1)), int(m.group(2))))
    return out


def _median(values: list[int]) -> int | None:
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) // 2


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out_log", help="Path to append sample lines")
    ap.add_argument("--logdir", default="", help="Directory with nfqws2_*.log debug files (default: XDG state logs dir)")
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--deadline", type=float, default=600.0)
    ap.add_argument("--marker", default="@/tmp/bs_hostnfq_", help="cmdline substring identifying our daemons")
    args = ap.parse_args()
    if not args.logdir:
        from blockchecks.engine.paths import RUNTIME_LOGS_DIR

        args.logdir = str(RUNTIME_LOGS_DIR)

    with open(args.out_log, "a", encoding="utf-8") as out:
        start = time.monotonic()
        rss_samples: list[int] = []
        seen_pids: set[int] = set()
        initial_pids: set[int] = set()
        respawns = 0
        offsets: dict[str, int] = {}
        gc_after: list[int] = []
        gc_count = 0
        max_rss = 0
        empty_streak = 0
        while time.monotonic() - start < args.deadline:
            pids, errors = _nfqws2_pids(args.marker)
            if pids:
                total = sum(_rss_kib(p) for p in pids)
                max_rss = max(max_rss, total)
                new = [p for p in pids if p not in seen_pids]
                seen_pids.update(pids)
                if initial_pids:
                    respawns += sum(1 for p in new if p not in initial_pids)
                else:
                    initial_pids = set(pids)
                rss_samples.append(total)
            gcs = _collect_gc(args.logdir, offsets)
            for before, after in gcs:
                gc_count += 1
                gc_after.append(after)
                out.write(f"gc before_kib={before} after_kib={after}\n")
                out.flush()
            out.write(
                f"snap ts={int(time.monotonic() - start)} "
                f"daemons={len(pids)} rss_total_kib={sum(_rss_kib(p) for p in pids)} "
                f"errors={errors}\n"
            )
            out.flush()
            if not pids and seen_pids:
                # Daemon gap: reboots (mem-pressure / debug toggle / retry)
                # create brief absences. Only end when the daemon stays gone
                # ~12 intervals (60s) — otherwise a mid-run reboot would
                # truncate a Stage A measurement (AUDIT §22 2026-10-01).
                empty_streak += 1
                if empty_streak >= 12:
                    break
            else:
                empty_streak = 0
            time.sleep(args.interval)

        n = len(rss_samples)
        first = _median(rss_samples[:3])
        last = _median(rss_samples[-3:]) if n >= 3 else _median(rss_samples)
        out.write(
            f"FINAL daemons={len(initial_pids)} rss_first={first or 0} "
            f"rss_last={last or 0} max_rss={max_rss} respawns={respawns} "
            f"gc_count={gc_count} "
            f"gc_after_first={gc_after[0] if gc_after else 0} "
            f"gc_after_last={gc_after[-1] if gc_after else 0}\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
