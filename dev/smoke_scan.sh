#!/usr/bin/env bash
# smoke_scan.sh — quick bs scan with a small known-good user matrix.
#
# Usage:
#   bash dev/smoke_scan.sh [backend] [domain]
#     backend: default | bridge | classic-maps
#   default/bridge run lua_bridge. classic-maps: deprecated --classic (maps).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BS="${BS:-$ROOT/.venv/bin/bs}"
BACKEND="${1:-default}"
DOMAIN="${2:-discord.com}"
TS="$(date +%Y%m%d_%H%M%S)"
LOG="logs/smoke_scan_${TS}.log"
DB="logs/smoke_scan_${TS}.db"
mkdir -p logs

STATE="${XDG_STATE_HOME:-$HOME/.local/state}/blockcheckS"
if [ -f "$STATE/run.lock" ]; then
  echo "ERROR: $STATE/run.lock present — refuse smoke_scan during a live campaign" >&2
  exit 2
fi

MATRIX=$(mktemp)
trap 'rm -f "$MATRIX"' EXIT
cat >"$MATRIX" <<'EOF'
fake:blob=stun:repeats=6:tcp_ts=-1000
fake:blob=max_ru:repeats=6:tcp_ts=-1000
fake:blob=google:repeats=6:tcp_ts=-1000
EOF

BACKEND_ARGS=()
case "$BACKEND" in
  default)  BACKEND_ARGS=() ;;
  bridge)   BACKEND_ARGS=(--probe-backend lua_bridge) ;;
  classic-maps|classic)  BACKEND_ARGS=(--classic) ;;
  *) echo "ERROR: unknown backend '$BACKEND' (default|bridge|classic-maps)" >&2; exit 2 ;;
esac

echo "=== smoke_scan backend=$BACKEND domain=$DOMAIN $(date -Is) ===" | tee "$LOG"
sudo -n env BLOCKCHECKS_PROBE_BACKEND= "$BS" scan \
  -d "$DOMAIN" \
  --user-matrix "$MATRIX" \
  --max 3 --parallel 1 \
  --scan-level fast \
  --skip-deps-check --skip-dns-audit --skip-prolog \
  --skip-ip-block --skip-port-block --skip-baseline \
  --no-wssize --quick --timeout 8 --db "$DB" \
  "${BACKEND_ARGS[@]}" 2>&1 | tee -a "$LOG"

echo "=== log: $LOG ==="
"$ROOT/.venv/bin/python3" "$ROOT/dev/assert_smoke_db.py" --db "$DB" --log "$LOG" --require-backend
