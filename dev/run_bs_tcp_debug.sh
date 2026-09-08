#!/bin/bash
set -euo pipefail
cd /home/zhoel/workspace/blockcheckS
if pgrep -x nfqws2 >/dev/null 2>&1; then
  echo "WARNING: nfqws2 is running; NOT killing host-wide (would hit nfqws2 in ALL netns — AGENTS.md §8)." >&2
  echo "WARNING: bs tcp manages its own daemon; if a stale host daemon holds the queue, stop it explicitly." >&2
fi
export BLOCKCHECKS_NFQWS2_DEBUG=1
.venv/bin/bs tcp -d discord.com \
  -s 'fake:blob=stun:repeats=6:tcp_ts=-1000' \
  --timeout 8 \
  --nfqws2-debug 2>&1 | tee /tmp/bs_tcp_debug_run.txt | tail -50
echo "==== logs ===="
ls -lt logs/nfqws2_*.log 2>/dev/null | head -5 || true
L=$(ls -t logs/nfqws2_*.log 2>/dev/null | head -1 || true)
echo "LOG=$L"
if [ -n "${L:-}" ]; then
  wc -c "$L"
  echo "---- tail ----"
  tail -60 "$L"
fi
