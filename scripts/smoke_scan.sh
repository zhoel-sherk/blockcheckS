#!/usr/bin/env bash
# smoke_scan.sh — quick bs scan with a small known-good user matrix.
#
# Usage:
#   scripts/smoke_scan.sh [backend] [domain]
#     backend: default | classic | bridge | compare   (default: default)
#     domain:  host to scan (default discord.com)
#
# Backend selection:
#   default  → no flag (lua_bridge is standard)
#   classic  → --classic
#   bridge   → --probe-backend lua_bridge
#   compare  → --lua-bridge-compare (dual path + drift log)
#
# Verifies the chosen backend appears in the batch line and prints PASS/FAIL.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BS="${BS:-$ROOT/.venv/bin/bs}"
BACKEND="${1:-default}"
DOMAIN="${2:-discord.com}"
LOG="logs/smoke_scan_$(date +%Y%m%d_%H%M%S).log"
mkdir -p logs

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
  classic)  BACKEND_ARGS=(--classic) ;;
  bridge)   BACKEND_ARGS=(--probe-backend lua_bridge) ;;
  compare)  BACKEND_ARGS=(--lua-bridge-compare) ;;
  *) echo "ERROR: unknown backend '$BACKEND' (default|classic|bridge|compare)" >&2; exit 2 ;;
esac

echo "=== smoke_scan backend=$BACKEND domain=$DOMAIN $(date -Is) ===" | tee "$LOG"
sudo -n env BLOCKCHECKS_PROBE_BACKEND= "$BS" scan \
  -d "$DOMAIN" \
  --user-matrix "$MATRIX" \
  --max 3 --parallel 1 \
  --scan-level fast \
  --skip-deps-check --skip-dns-audit --skip-prolog \
  --skip-ip-block --skip-port-block --skip-baseline \
  --no-wssize --quick --timeout 8 \
  "${BACKEND_ARGS[@]}" 2>&1 | tee -a "$LOG"

echo "=== log: $LOG ==="
