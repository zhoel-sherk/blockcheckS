#!/usr/bin/env bash
# smoke_all.sh — 1.3.7 pre-release campaign: every existing smoke + flag coverage.
# Wall budget 90 minutes. Each step is timeboxed; leftovers are cleaned between lives.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TS="$(date +%Y%m%d_%H%M%S)"
OUT="logs/smoke_all_${TS}"
mkdir -p "$OUT"
export DIR="$OUT/flags"
BUDGET="${SMOKE_ALL_BUDGET_SEC:-5400}"
START=$SECONDS
DEADLINE=$((START + BUDGET))
PASS=0
FAIL=0
SKIP=0
FAILED=()
SKIPPED=()

remain() { echo $((DEADLINE - SECONDS)); }
too_late() { [[ $SECONDS -ge $DEADLINE ]]; }

log() { printf '\n######## [%s] %s  (remain %ss) ########\n' "$(date +%H:%M:%S)" "$1" "$(remain)" | tee -a "$OUT/summary.log"; }

cleanup() {
  bash "$ROOT/scripts/cleanup_env.sh" >>"$OUT/cleanup.log" 2>&1 || true
}

run() { # run <label> <timeout-sec> <cmd...>
  local label="$1" need="$2" t="$2"
  shift 2
  if too_late; then
    echo "SKIP $label (budget)" | tee -a "$OUT/summary.log"
    SKIP=$((SKIP+1)); SKIPPED+=("$label"); return 0
  fi
  local left; left=$(remain)
  if [[ "$t" -gt "$left" ]]; then t=$left; fi
  if [[ "$t" -lt 30 ]]; then
    echo "SKIP $label (need ${need}s, left ${left}s)" | tee -a "$OUT/summary.log"
    SKIP=$((SKIP+1)); SKIPPED+=("$label"); return 0
  fi
  log "$label  timeout=${t}s"
  cleanup
  local rc=0
  if timeout --kill-after=20s "${t}s" "$@" >"$OUT/${label}.log" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  cleanup
  if [[ $rc -eq 0 ]]; then
    echo "PASS $label" | tee -a "$OUT/summary.log"
    PASS=$((PASS+1))
  elif [[ $rc -eq 124 || $rc -eq 137 ]]; then
    echo "TIMEOUT $label rc=$rc" | tee -a "$OUT/summary.log"
    FAIL=$((FAIL+1)); FAILED+=("$label:timeout")
  else
    echo "FAIL $label rc=$rc" | tee -a "$OUT/summary.log"
    FAIL=$((FAIL+1)); FAILED+=("$label:rc=$rc")
    tail -20 "$OUT/${label}.log" | tee -a "$OUT/summary.log"
  fi
}

echo "smoke_all $TS budget=${BUDGET}s" | tee "$OUT/summary.log"
echo "host=$(hostname) bs=$ROOT/.venv/bin/bs" | tee -a "$OUT/summary.log"

# Offline / unit first (no nfqws2 contention)
run gate_all 180 bash "$ROOT/dev/gate_all.sh"
run smoke_flags 1500 bash "$ROOT/dev/smoke_flags.sh"
run functional_smoke 1200 bash "$ROOT/dev/functional_smoke.sh"
run smoke_backend_matrix 600 bash "$ROOT/dev/smoke_backend_matrix.sh"
run smoke_20min 2700 bash "$ROOT/dev/smoke_20min.sh"
run voice_smoke 180 bash "$ROOT/dev/voice_smoke.sh"
run gv1_smoke 240 bash "$ROOT/dev/gv1_smoke.sh"
run smoke_full_quick 180 bash "$ROOT/dev/smoke_full_quick.sh"
run smoke_scan 180 bash "$ROOT/dev/smoke_scan.sh"
# fan-out can hang past --max-timem; keep a hard cap
run release_smoke 1080 bash "$ROOT/dev/release_smoke.sh"

cleanup
{
  echo
  echo "======== RESULT smoke_all $TS ========"
  echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP elapsed=$((SECONDS-START))s"
  if [[ ${#FAILED[@]} -gt 0 ]]; then printf 'FAILED: %s\n' "${FAILED[@]}"; fi
  if [[ ${#SKIPPED[@]} -gt 0 ]]; then printf 'SKIPPED: %s\n' "${SKIPPED[@]}"; fi
  echo "logs: $OUT"
} | tee -a "$OUT/summary.log"

[[ $FAIL -eq 0 ]]
