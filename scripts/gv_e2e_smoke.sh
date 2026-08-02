#!/usr/bin/env bash
# GV e2e smoke: googlevideo.com videoplayback + hostfakesplit/fake strategies.
# Validates GV-1 (yt-dlp URL) and GV-3 (curl_probe) end-to-end through nfqws2 netns.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PWD}/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  echo "ERROR: .venv not found — run: pip install -e '.[dev,youtube]'" >&2
  exit 1
fi
LOG="logs/gv_e2e_smoke_$(date +%Y%m%d_%H%M%S).log"
mkdir -p logs
echo "=== GV e2e smoke $(date -Is) ===" | tee "$LOG"
echo "--- yt-dlp URL check ---" | tee -a "$LOG"
PYTHONPATH=src "$PY" -c "
from blockchecks.checkers.youtube_url import get_fresh_url, videoplayback_host
u = get_fresh_url()
print('fresh_url:', 'OK' if u else 'FAIL')
if u:
    print('host:', videoplayback_host(u))
" 2>&1 | tee -a "$LOG"
echo "--- bs tcp googlevideo.com (gv-e2e-smoke.tls) ---" | tee -a "$LOG"
sudo env PYTHONPATH="${PWD}/src" "$PY" -m blockchecks.bs tcp \
  -d googlevideo.com \
  -f presets/strategies/gv-e2e-smoke.tls \
  --timeout 8 \
  --skip-dns-audit 2>&1 | tee -a "$LOG"
RC=${PIPESTATUS[0]}
echo "exit_code=$RC" | tee -a "$LOG"
echo "Log: $LOG"
exit "$RC"
