#!/bin/bash
set -euo pipefail
cd /home/zhoel/workspace/blockcheckS
sudo -n pkill -9 nfqws2 2>/dev/null || true
sleep 0.5
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
