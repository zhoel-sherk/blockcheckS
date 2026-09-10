#!/usr/bin/env python3
"""Step 11 sampler (smoke_long): inproc probe worker stability probes.

Samples the `bs scan` runner process every second and appends to the log:
- VmHWM (peak RSS) growth over the run — memory leak detector;
- open fd count growth — setns fd leak detector (2 fds per probe invoke);
- per-thread netns inodes of the runner — a thread still inside the probe
  netns between probes means a restore leak.
Exits when the scan process disappears (after having seen it at least once).
"""

import os
import subprocess
import sys
import time

out_log = sys.argv[1]
deadline = time.monotonic() + 240
first_hwm = 0
last_hwm = 0
fd_first = 0
fd_last = 0
samples = 0
host_inode = ""
stuck_ns_samples = 0

while time.monotonic() < deadline:
    pids = subprocess.run(
        ["pgrep", "-f", "venv/bin/bs scan"], capture_output=True, text=True
    ).stdout.split()
    best = 0
    best_pid = 0
    for pid in pids:
        try:
            cmd = open(f"/proc/{pid}/cmdline", "rb").read().decode("utf-8", "replace")
            if "python" not in cmd:
                continue
            hwm = 0
            for ln in open(f"/proc/{pid}/status"):
                if ln.startswith("VmHWM"):
                    hwm = int(ln.split()[1])
            # track the pid with the LARGEST HWM (the runner is by far the
            # heaviest python matching; short-lived sudo/ip helpers otherwise
            # hijack best_pid and poison the fd sampling — smoke 2026-09-10).
            if hwm > best:
                best = hwm
                best_pid = pid
        except OSError:
            continue
    if best and best_pid:
        samples += 1
        if first_hwm == 0:
            first_hwm = best
        last_hwm = max(last_hwm, best)
        try:
            fds = len(os.listdir(f"/proc/{best_pid}/fd"))
            if fd_first == 0:
                fd_first = fds
            fd_last = fds
        except OSError:
            pass
        # per-thread netns check: every thread must sit on the HOST inode
        try:
            if not host_inode:
                host_inode = os.readlink(f"/proc/self/ns/net")
            tasks = os.listdir(f"/proc/{best_pid}/task")
            for tid in tasks:
                try:
                    ino = os.readlink(f"/proc/{best_pid}/task/{tid}/ns/net")
                except OSError:
                    continue
                if ino != host_inode:
                    stuck_ns_samples += 1
        except OSError:
            pass
        with open(out_log, "a") as f:
            f.write(
                f"snap samples={samples} hwm_kib={best} fd={fd_last} "
                f"stuck_ns={stuck_ns_samples}\n"
            )
    if not pids and samples:
        break
    time.sleep(1.0)

# final worker count: real python workers only (cmdline contains BOTH
# 'python' and the worker marker) — pgrep -f self-matches the checking
# shell's own cmdline otherwise (smoke false FAIL 2026-09-10).
workers_final = 0
for pid in subprocess.run(
    ["pgrep", "-f", "in_ns_workers --mode curl"], capture_output=True, text=True
).stdout.split():
    try:
        cmd = open(f"/proc/{pid}/cmdline", "rb").read().decode("utf-8", "replace")
        if "python" in cmd:
            workers_final += 1
    except OSError:
        continue

with open(out_log, "a") as f:
    f.write(
        f"FINAL hwm_first={first_hwm} hwm_last={last_hwm} "
        f"fd_first={fd_first} fd_last={fd_last} stuck_ns_total={stuck_ns_samples} "
        f"workers_final={workers_final}\n"
    )
