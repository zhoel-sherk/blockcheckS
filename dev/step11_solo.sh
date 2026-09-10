#!/usr/bin/env bash
# Step 11 solo revalidation (same criteria as smoke_long step_body_11).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BS="${BS:-$ROOT/.venv/bin/bs}"
PY="${PY:-$ROOT/.venv/bin/python3}"
TS=$(date +%Y%m%d_%H%M%S)
DIR="logs/smoke_step11_${TS}"
mkdir -p "$DIR"
LOG11="$DIR/step11_inproc.log"
SNAPLOG="$DIR/step11_snap.log"
: > "$SNAPLOG"
sudo -n "$BS" scan -d discord.com --generate --max 8 --parallel 2 \
  --probe-worker=inproc --timeout 4 --skip-deps-check --skip-dns-audit \
  2>&1 | tee "$LOG11" >/dev/null &
SCAN_PID=$!
"$PY" "$ROOT/dev/step11_snap.py" "$SNAPLOG" &
SNAP_PID=$!
wait $SCAN_PID || true
wait $SNAP_PID 2>/dev/null || true
SCAN_SUM=$(grep -a "TCP discord" "$LOG11" | sed 's/\x1b\[[0-9;]*m//g' | grep -aE "TCP [a-z.]+: [0-9]+/[0-9]+ passed" || true)
if [[ -n "$SCAN_SUM" ]]; then
  echo "OK: inproc scan completed"
else
  echo "FAIL: inproc scan failed"; tail -6 "$LOG11"
fi
if grep -aq "abort_poll ignored" "$LOG11" && ! grep -aq "inproc setns: EPERM" "$LOG11"; then
  echo "OK: inproc active (no EPERM fallback)"
else
  echo "FAIL: inproc not active"
fi
F1=$(grep -a "FINAL" "$SNAPLOG" | tail -1 || true)
echo "SNAP: $F1"
PLAT_A=$(sed -n '1,3{s/.*hwm_kib=\([0-9]*\).*/\1/p}' "$SNAPLOG" | sort -n | sed -n '2p' || true)
PLAT_B=$(grep -a "^snap " "$SNAPLOG" | sed -n 's/.*hwm_kib=\([0-9]*\).*/\1/p' | sort -n | tail -2 | sed -n '1p' || true)
echo "PLATEAU: +$(( (PLAT_B - PLAT_A) / 1024 )) MiB"
if grep -aq "setns back to host ns failed" "$LOG11"; then
  echo "FAIL: setns restore error present"
else
  echo "OK: all setns restores clean"
fi
STUCK=$(echo "$F1" | sed -n 's/.*stuck_ns_total=\([0-9]*\).*/\1/p')
echo "INFO: stuck_ns_during_probes=$STUCK (expected >0 mid-run — that is the design)"
ALIVE=$(echo "$F1" | sed -n 's/.*workers_final=\([0-9]*\).*/\1/p')
if [[ "${ALIVE:-99}" -le 0 ]]; then
  echo "OK: no persistent curl workers (real=$ALIVE)"
else
  echo "FAIL: persistent curl workers alive: $ALIVE"
fi
echo "LOGS: $DIR"
