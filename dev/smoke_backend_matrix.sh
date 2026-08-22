#!/usr/bin/env bash
# smoke_backend_matrix.sh — functional test of probe-backend selection.
#
# Runs the same tiny user matrix through every backend mode and asserts the
# correct backend appears in the batch line:
#   default → backend=lua_bridge
#   classic → backend=classic          (--classic)
#   probe   → backend=classic          (--probe-backend)
#   env     → lua_bridge or classic    (BLOCKCHECKS_PROBE_BACKEND)
#   compare → two batches (classic + lua_bridge), no BRIDGE_DRIFT
#
# Fails (exit 1) if any backend line is missing or wrong.
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
  echo "$out" | grep -E "backend=|DRIFT|drift" | tee -a "$LOG"
  if ! echo "$out" | grep -q "backend=$expected"; then
    echo "FAIL: expected backend=$expected, got:" | tee -a "$LOG"
    echo "$out" | tail -5 | tee -a "$LOG"
    return 1
  fi
  echo "OK: $label → backend=$expected" | tee -a "$LOG"
}

FAILED=0

run_and_check "default(no flag)" "lua_bridge" || FAILED=1
run_and_check "--classic" "classic" --classic || FAILED=1
run_and_check "--probe-backend classic" "classic" --probe-backend classic || FAILED=1
run_and_check "--probe-backend lua_bridge" "lua_bridge" --probe-backend lua_bridge || FAILED=1

echo "--- env BLOCKCHECKS_PROBE_BACKEND=classic (no flag) ---" | tee -a "$LOG"
OUT_ENV=$(sudo -n env BLOCKCHECKS_PROBE_BACKEND=classic "$BS" scan "${COMMON[@]}" 2>&1 || true)
echo "$OUT_ENV" | grep "backend=" | tee -a "$LOG"
if ! echo "$OUT_ENV" | grep -q "backend=classic"; then
  echo "FAIL: env override did not force classic" | tee -a "$LOG"; FAILED=1
else
  echo "OK: env → backend=classic" | tee -a "$LOG"
fi

echo "--- compare (dual classic + lua_bridge) ---" | tee -a "$LOG"
OUT_CMP=$(sudo -n env -u BLOCKCHECKS_PROBE_BACKEND "$BS" scan "${COMMON[@]}" --lua-bridge-compare 2>&1 || true)
echo "$OUT_CMP" | grep -E "backend=|DRIFT" | tee -a "$LOG"
if echo "$OUT_CMP" | grep -q "DRIFT"; then
  echo "FAIL: BRIDGE_DRIFT detected in compare" | tee -a "$LOG"; FAILED=1
else
  echo "OK: compare — no drift" | tee -a "$LOG"
fi

echo ""
echo "=== backend matrix log: $LOG ==="
if [ "$FAILED" -eq 0 ]; then
  echo "ALL BACKEND CHECKS PASSED"
else
  echo "SOME BACKEND CHECKS FAILED" >&2
  exit 1
fi
