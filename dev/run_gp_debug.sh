#!/bin/bash
set -euo pipefail
cd /home/zhoel/workspace/blockcheckS
sudo -n pkill -9 nfqws2 2>/dev/null || true
sleep 0.5
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
