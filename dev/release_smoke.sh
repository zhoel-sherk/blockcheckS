#!/usr/bin/env bash
# Release smoke: benchmark preset, AQ fan-out, time limit (needs sudo + nfqws2).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TS="$(date +%Y%m%d_%H%M%S)"
LOG_DIR="logs/release_smoke_${TS}"
mkdir -p "$LOG_DIR"

# sudo does not inherit user PATH; prefer project venv.
BS="${BS:-$ROOT/.venv/bin/bs}"
PY="${PY:-$ROOT/.venv/bin/python3}"
if [[ ! -x "$BS" ]]; then
  BS="$(command -v bs)"
fi
if [[ ! -x "$PY" ]]; then
  PY="$(command -v python3)"
fi

echo "=== blockcheckS release smoke ($TS) ==="
echo "bs=$BS py=$PY"

# Внешний timeout: fan-out известен выходами за внутренний --max-timem,
# зависший процесс оставлял бы netns без teardown.
REL_TIMEOUT="${REL_TIMEOUT:-1080}"
timeout --kill-after=20s "${REL_TIMEOUT}" sudo "$BS" full \
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

# sudo creates root-owned DB; reclaim for user-space export/import
if [[ -n "${SUDO_USER:-}" ]]; then
  sudo chown "${SUDO_USER}:" "${LOG_DIR}/state.db" "${LOG_DIR}/state.db"-* 2>/dev/null || \
    sudo chown "${SUDO_USER}:" "${LOG_DIR}/state.db" 2>/dev/null || true
elif [[ -n "${USER:-}" ]]; then
  sudo chown "${USER}:" "${LOG_DIR}/state.db" "${LOG_DIR}/state.db"-* 2>/dev/null || \
    sudo chown "${USER}:" "${LOG_DIR}/state.db" 2>/dev/null || true
fi

echo "=== AQ benchmark ==="
"$PY" dev/aq_benchmark.py --db "${LOG_DIR}/state.db" | tee "${LOG_DIR}/aq_report.txt"

echo "=== Shortlist export ==="
"$PY" -m blockchecks.shortlist_export \
  --db "${LOG_DIR}/state.db" \
  -o "${LOG_DIR}/shortlist.json"

echo "=== B5 round-trip: shortlist → presets (local) ==="
IMPORT_DIR="${LOG_DIR}/import_presets"
mkdir -p "$IMPORT_DIR"
if "$PY" -c "import json,sys; d=json.load(open('${LOG_DIR}/shortlist.json')); sys.exit(0 if (d.get('tcp') or d.get('common_tcp')) else 1)"; then
  "$PY" -m blockchecks.shortlist_import \
    -i "${LOG_DIR}/shortlist.json" \
    --out-dir "${IMPORT_DIR}" \
    --prefix smoke \
    | tee "${LOG_DIR}/roundtrip.log"
else
  echo "SKIP: shortlist empty (no TCP PASS in run) — round-trip not exercised" | tee "${LOG_DIR}/roundtrip.log"
fi

echo "Done. Artifacts: ${LOG_DIR}/"
