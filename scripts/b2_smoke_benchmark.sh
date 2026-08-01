#!/usr/bin/env bash
# B2 smoke: compare curl-parallel 1 vs 4 on benchmark preset (needs sudo + nfqws2).
set -euo pipefail
cd "$(dirname "$0")/.."
LOG=logs/b2_smoke_$(date +%Y%m%d_%H%M%S).log
mkdir -p logs
COMMON=(
  --domains-file presets/domains/benchmark.txt
  --max 24
  --parallel 2
  --scan-level fast
  --tcp-only
  --no-http
  --no-quic
  --no-voice
  --skip-dns-audit
  --force
  --db logs/b2_smoke.db
)
run_one() {
  local label=$1
  local cp=$2
  echo "=== $label curl-parallel=$cp $(date -Is) ===" | tee -a "$LOG"
  local t0=$(date +%s)
  sudo -E python3 -m blockchecks.bs full "${COMMON[@]}" --curl-parallel "$cp" \
    --no-settle-profile 2>&1 | tee -a "$LOG"
  local t1=$(date +%s)
  echo "=== $label elapsed=$((t1 - t0))s ===" | tee -a "$LOG"
}
run_one serial 1
run_one fanout 4
echo "Log: $LOG"
