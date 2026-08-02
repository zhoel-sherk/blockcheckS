#!/usr/bin/env bash
# Release smoke: benchmark preset, AQ fan-out, time limit (needs sudo + nfqws2).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TS="$(date +%Y%m%d_%H%M%S)"
LOG_DIR="logs/release_smoke_${TS}"
mkdir -p "$LOG_DIR"

echo "=== blockcheckS release smoke ($TS) ==="

sudo bs full \
  --fan-out \
  --allow-dns-hijack \
  --domains-file presets/domains/benchmark.txt \
  --scan-level fast \
  --max 50 \
  --parallel 4 \
  --tcp-only \
  --no-http \
  --no-quic \
  --max-timem 15 \
  --db "${LOG_DIR}/state.db" \
  --out-dir "${LOG_DIR}/export" \
  2>&1 | tee "${LOG_DIR}/run.log"

echo "=== AQ benchmark ==="
python3 scripts/aq_benchmark.py --db "${LOG_DIR}/state.db" | tee "${LOG_DIR}/aq_report.txt"

echo "=== Shortlist export ==="
python3 -m blockchecks.shortlist_export \
  --db "${LOG_DIR}/state.db" \
  -o "${LOG_DIR}/shortlist.json"

echo "Done. Artifacts: ${LOG_DIR}/"
