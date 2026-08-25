#!/usr/bin/env bash
# GV-1 smoke: googlevideo.com videoplayback probe via bs full (needs sudo + nfqws2).
# GGC binary probe is the default; yt-dlp only as fallback via BLOCKCHECKS_GV_GGC=0.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PWD}/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  echo "ERROR: .venv not found — run: pip install -e '.[dev,youtube]'" >&2
  exit 1
fi
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
echo "googlevideo.com" > "$TMP"
LOG=logs/gv1_smoke_$(date +%Y%m%d_%H%M%S).log
mkdir -p logs
echo "=== GV-1 smoke $(date -Is) ===" | tee "$LOG"
sudo env PYTHONPATH="${PWD}/src" "$PY" -m blockchecks.bs full \
  --domains-file "$TMP" \
  --max 6 \
  --parallel 2 \
  --scan-level fast \
  --tcp-only \
  --no-http \
  --no-quic \
  --no-voice \
  --skip-dns-audit \
  --skip-ip-block \
  --skip-port-block \
  --force \
  --no-settle-profile \
  --db logs/gv1_smoke.db 2>&1 | tee -a "$LOG"
echo "Log: $LOG"
