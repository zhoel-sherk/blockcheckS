#!/usr/bin/env bash
# Voice UDP smoke: dns-alive discover + discord_udp nfqws2 probe.
# Needs sudo + nfqws2 + blobs/discord_udp.bin. Optional --full-voice if token present.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PWD}/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  echo "ERROR: .venv not found — run: pip install -e '.[dev]'" >&2
  exit 1
fi
LOG="logs/voice_smoke_$(date +%Y%m%d_%H%M%S).log"
mkdir -p logs
UDP_CONF="${UDP_CONF:-configs/udp_voice__fake_r6.conf}"
DISCOVER_N="${DISCOVER_N:-2}"
echo "=== Voice UDP smoke $(date -Is) ===" | tee "$LOG"
echo "config=$UDP_CONF discover-dns=$DISCOVER_N" | tee -a "$LOG"
sudo env PYTHONPATH="${PWD}/src" "$PY" -m blockchecks.bs udp \
  -c "$UDP_CONF" \
  --discover-dns "$DISCOVER_N" \
  --timeout 5 \
  --skip-deps-check 2>&1 | tee -a "$LOG"
RC=${PIPESTATUS[0]}
# Optional full-voice pair probe when Discord token settings exist
SETTINGS="${DPI_TESTER_SETTINGS:-}"
if [[ -z "$SETTINGS" ]]; then
  for cand in settings.ini ../dpi-tester/settings.ini; do
    if [[ -f "$cand" ]]; then SETTINGS="$cand"; break; fi
  done
fi
if [[ -n "${SETTINGS}" && -f "${SETTINGS}" ]] && grep -qE '^[[:space:]]*token[[:space:]]*=' "$SETTINGS" 2>/dev/null; then
  echo "--- optional pair --full-voice (token present) ---" | tee -a "$LOG"
  sudo env PYTHONPATH="${PWD}/src" "$PY" -m blockchecks.bs pair \
    -d discord.com \
    -c configs/simple_fake_alt2__fake_max_ru_ts.conf \
    -u "$UDP_CONF" \
    --discover-dns "$DISCOVER_N" \
    --full-voice \
    --max 1 \
    --parallel 1 \
    --scan-level single \
    --skip-dns-audit \
    --force 2>&1 | tee -a "$LOG" || true
fi
echo "exit_code=$RC" | tee -a "$LOG"
echo "Log: $LOG"
exit "$RC"
