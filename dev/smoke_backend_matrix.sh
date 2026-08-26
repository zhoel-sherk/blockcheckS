#!/usr/bin/env bash
# smoke_backend_matrix.sh — campaign TCP is lua_bridge only.
#
# --classic / env classic still parse and must log mapping + backend=lua_bridge.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BS="${BS:-$ROOT/.venv/bin/bs}"
DOMAIN="${1:-discord.com}"
TS="$(date +%Y%m%d_%H%M%S)"
LOG="logs/backend_matrix_${TS}.log"
mkdir -p logs

MATRIX=$(mktemp)
trap 'rm -f "$MATRIX"' EXIT
printf 'fake:blob=stun:repeats=6:tcp_ts=-1000\nfake:blob=max_ru:repeats=6:tcp_ts=-1000\n' >"$MATRIX"

COMMON=(
  -d "$DOMAIN" --user-matrix "$MATRIX"
  --max 2 --parallel 1 --scan-level fast
  --skip-deps-check --skip-dns-audit --skip-prolog
  --skip-ip-block --skip-port-block --skip-baseline
  --no-wssize --quick --timeout 8
)

run_and_check() {
  local label="$1"; shift
  local expected="$1"; shift
  local out
  out=$(sudo -n env -u BLOCKCHECKS_PROBE_BACKEND "$BS" scan "${COMMON[@]}" "$@" 2>&1 || true)
  echo "--- $label ---" | tee -a "$LOG"
  echo "$out" | grep -E "backend=|deprecated|mapping to lua_bridge" | tee -a "$LOG"
  if ! echo "$out" | grep -q "backend=$expected"; then
    echo "FAIL: expected backend=$expected, got:" | tee -a "$LOG"
    echo "$out" | tail -5 | tee -a "$LOG"
    return 1
  fi
  echo "OK: $label → backend=$expected" | tee -a "$LOG"
}

FAILED=0

run_and_check "default(no flag)" "lua_bridge" || FAILED=1
run_and_check "--classic (maps)" "lua_bridge" --classic || FAILED=1
run_and_check "--probe-backend classic (maps)" "lua_bridge" --probe-backend classic || FAILED=1
run_and_check "--probe-backend lua_bridge" "lua_bridge" --probe-backend lua_bridge || FAILED=1

echo "--- env BLOCKCHECKS_PROBE_BACKEND=classic (maps) ---" | tee -a "$LOG"
OUT_ENV=$(sudo -n env BLOCKCHECKS_PROBE_BACKEND=classic "$BS" scan "${COMMON[@]}" 2>&1 || true)
echo "$OUT_ENV" | grep -E "backend=|mapping to lua_bridge" | tee -a "$LOG"
if ! echo "$OUT_ENV" | grep -q "backend=lua_bridge"; then
  echo "FAIL: env classic did not map to lua_bridge" | tee -a "$LOG"; FAILED=1
else
  echo "OK: env classic → backend=lua_bridge" | tee -a "$LOG"
fi

echo ""
echo "=== backend matrix log: $LOG ==="
if [ "$FAILED" -eq 0 ]; then
  echo "ALL BACKEND CHECKS PASSED"
else
  echo "SOME BACKEND CHECKS FAILED" >&2
  exit 1
fi
