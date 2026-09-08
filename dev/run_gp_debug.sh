#!/bin/bash
set -euo pipefail
cd /home/zhoel/workspace/blockcheckS
if pgrep -x nfqws2 >/dev/null 2>&1; then
  echo "WARNING: nfqws2 is running; NOT killing host-wide (would hit nfqws2 in ALL netns — AGENTS.md §8)." >&2
  echo "WARNING: bs tcp manages its own daemon; if a stale host daemon holds the queue, stop it explicitly." >&2
fi
export BLOCKCHECKS_NFQWS2_DEBUG=1
# First 3 GP-verified strategies
.venv/bin/bs tcp -d discord.com \
  -f presets/strategies/gp-verified.tls \
  --timeout 6 \
  --nfqws2-debug 2>&1 | tee /tmp/bs_gp_debug.txt
echo "==== recent debug logs ===="
ls -lt logs/nfqws2_q200_*.log | head -5
echo "==== profiles from latest 3 logs ===="
for f in $(ls -t logs/nfqws2_q200_*.log | head -3); do
  echo "-- $f"
  grep -E "profile 1|blob '|read .*blobs" "$f" || true
done
