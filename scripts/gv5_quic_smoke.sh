#!/usr/bin/env bash
# GV-5 QUIC smoke: HTTP/3 on googlevideo.com with kyber QUIC blobs.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PWD}/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  echo "ERROR: .venv not found — run: pip install -e '.[dev,youtube]'" >&2
  exit 1
fi

if [[ ! -f /opt/zapret2/blobs/quic_gv_kyber_1.bin ]]; then
  echo "--- installing GV kyber blobs ---" 
  bash scripts/install_blobs.sh
fi

LOG="logs/gv5_quic_smoke_$(date +%Y%m%d_%H%M%S).log"
mkdir -p logs
echo "=== GV-5 QUIC smoke $(date -Is) ===" | tee "$LOG"
echo "--- blob aliases ---" | tee -a "$LOG"
PYTHONPATH=src "$PY" -c "
from blockchecks.engine.blob_aliases import resolve_blob_path
for name in ('quic_gv_kyber_1', 'quic_gv_kyber_2', 'quic_google'):
    print(name, '->', resolve_blob_path(name))
" 2>&1 | tee -a "$LOG"

echo "--- bs quic googlevideo.com (gv5-quic-smoke.quic) ---" | tee -a "$LOG"
sudo env PYTHONPATH="${PWD}/src" "$PY" -m blockchecks.bs tcp \
  -d googlevideo.com \
  -f presets/strategies/gv5-quic-smoke.quic \
  --protocol quic \
  --timeout 10 \
  --skip-dns-audit 2>&1 | tee -a "$LOG"
RC=${PIPESTATUS[0]}
echo "exit_code=$RC" | tee -a "$LOG"
echo "Log: $LOG"
exit "$RC"
