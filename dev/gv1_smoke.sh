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
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/blockcheckS"
if [ -f "$STATE/run.lock" ]; then
  echo "ERROR: $STATE/run.lock present — refuse gv1_smoke" >&2
  exit 2
fi
TMP=$(mktemp)
cleanup_run() {
  rm -f "$TMP"
  sudo -n "${PWD}/.venv/bin/bs" stop --wait 2 >/dev/null 2>&1 || true
  bash "${PWD}/scripts/cleanup_env.sh" >/dev/null 2>&1 || true
}
trap cleanup_run EXIT
bash "${PWD}/dev/smoke_host_reset.sh"
echo "googlevideo.com" > "$TMP"
LOG=logs/gv1_smoke_$(date +%Y%m%d_%H%M%S).log
mkdir -p logs
echo "=== GV-1 smoke $(date -Is) ===" | tee "$LOG"
set +e
timeout --foreground --kill-after=10s 120s sudo env PYTHONPATH="${PWD}/src" "$PY" -m blockchecks.bs full \
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
  --no-use-settle-profile \
  --db logs/gv1_smoke.db 2>&1 | tee -a "$LOG"
set -e
echo "Log: $LOG"
