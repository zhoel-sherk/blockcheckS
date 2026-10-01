#!/usr/bin/env bash
# Step 12 solo revalidation (same criteria as smoke_long step_body_12):
# Mode A daemon memory — scan runs with BLOCKCHECKS_BRIDGE_MODE=A while
# dev/step12_nfqws2_snap.py samples daemon RSS + LUA GARBAGE COLLECT pairs.
# Run via sudo (sampler reads /proc of the setuid overflow-uid daemon).
# NETNS Mode A (host-slot heartbeat is flaky under load — pre-existing,
# separate issue; netns is the stable measurement path, AUDIT §22).
# BLOCKCHECKS_LUA_GC_SEC shortens the forced-GC cadence for dense samples.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BS="${BS:-$ROOT/.venv/bin/bs}"
PY="${PY:-$ROOT/.venv/bin/python3}"
TS=$(date +%Y%m%d_%H%M%S)
DIR="logs/smoke_step12_${TS}"
mkdir -p "$DIR"
LOG12="$DIR/step12_modea.log"
SNAPLOG="$DIR/step12_snap.log"
: > "$SNAPLOG"
DEBUG="${BLOCKCHECKS_NFQWS2_DEBUG:-1}"
LUA_GC="${BLOCKCHECKS_LUA_GC_SEC:-10}"
# User home (SUDO_USER), not $HOME which is /root under sudo — debug logs land
# in the real user's XDG state dir via paths.py (SUDO_USER-aware).
UH="${SUDO_USER:+$(eval echo "~$SUDO_USER")}"
UH="${UH:-$HOME}"
LOGDIR="${BLOCKCHECKS_LOG_DIR:-$UH/.local/state/blockcheckS/logs}"
# Valid known-good matrix (NOT --generate: generated strategies carry
# fake_default_* built-in blobs → "unresolvable" → fence timeout + 0/N,
# pre-existing §6.2 gap, out of this wave's scope).
MATRIX="${MATRIX:-/tmp/step12_matrix.txt}"
if [[ ! -s "$MATRIX" ]]; then
  cat > "$MATRIX" << 'EOF'
fake:blob=stun:repeats=6:tcp_ts=-1000
fake:blob=max_ru:repeats=6:tcp_ts=-1000
fake:blob=google:repeats=6:tcp_ts=-1000
fake:blob=b4pda:repeats=6:tcp_ts=-1000
fake:blob=stun:repeats=6:tcp_ts=-1000:auto_fmt=autottl
fake:blob=max_ru:repeats=6:tcp_ts=-1000:auto_fmt=autottl
fake:blob=stun:repeats=6
fake:blob=max_ru:repeats=6
fake:blob=google:repeats=6
hostfakesplit:disorder_after:nofake2:tcp_ack=-66000:tcp_ts_up:repeats=1
fakedsplit:disorder_after:nofake2:disorder_1
multisplit:disorder_after:nofake2:disorder_1
syndata:pos=1
EOF
fi
sudo -n -E env BLOCKCHECKS_BRIDGE_MODE=A BLOCKCHECKS_NFQWS2_DEBUG="$DEBUG" \
  BLOCKCHECKS_LUA_GC_SEC="$LUA_GC" "$BS" scan -d discord.com --user-matrix "$MATRIX" \
  --max 20 --timeout 6 --skip-deps-check --skip-dns-audit \
  --scan-level fast --parallel 1 --repeats 3 2>&1 | tee "$LOG12" >/dev/null &
SCAN_PID=$!
sudo -n "$PY" "$ROOT/dev/step12_nfqws2_snap.py" "$SNAPLOG" --logdir "$LOGDIR" \
  --interval 5 --deadline 600 --marker "@/tmp/bs_" &
SNAP_PID=$!
wait $SCAN_PID || true
wait $SNAP_PID 2>/dev/null || true
SCAN_SUM=$(grep -a "TCP discord" "$LOG12" | sed 's/\x1b\[[0-9;]*m//g' | grep -aE "TCP [a-z.]+: [0-9]+/[0-9]+ passed" || true)
if [[ -n "$SCAN_SUM" ]]; then
  echo "OK: Mode A scan completed"
else
  echo "FAIL: Mode A scan failed"; tail -8 "$LOG12"
fi
F1=$(grep -a "FINAL" "$SNAPLOG" | tail -1 || true)
echo "SNAP: $F1"
GC=$(echo "$F1" | sed -n 's/.*gc_count=\([0-9]*\).*/\1/p')
if [[ "${GC:-0}" -ge 2 ]]; then
  echo "OK: gc samples present ($GC)"
else
  echo "FAIL: expected >=2 LUA GARBAGE COLLECT samples, got ${GC:-0}"
fi
# Lua heap after GC must be FLAT (plan instances do not accumulate). Allow
# a generous band: last within 1.5x of first (a single churn spike is OK).
GAF=$(echo "$F1" | sed -n 's/.*gc_after_first=\([0-9]*\).*/\1/p')
GAL=$(echo "$F1" | sed -n 's/.*gc_after_last=\([0-9]*\).*/\1/p')
if [[ -n "$GAF" && -n "$GAL" && $((GAL)) -le $((GAF * 15 / 10 + 64)) ]]; then
  echo "OK: Lua heap after GC flat (${GAF}K -> ${GAL}K)"
else
  echo "FAIL: Lua heap after GC grew: ${GAF:-?}K -> ${GAL:-?}K"
fi
PLAT_A=$(echo "$F1" | sed -n 's/.*rss_first=\([0-9]*\).*/\1/p')
PLAT_B=$(echo "$F1" | sed -n 's/.*rss_last=\([0-9]*\).*/\1/p')
if [[ -n "$PLAT_A" && -n "$PLAT_B" && $((PLAT_B - PLAT_A)) -le 15360 ]]; then
  echo "OK: RSS plateau (+$(( (PLAT_B - PLAT_A) / 1024 )) MiB)"
else
  echo "FAIL: RSS growth suspicious: ${PLAT_A:-?}KiB -> ${PLAT_B:-?}KiB"
fi
if grep -aq "daemon reboots total=" "$LOG12"; then
  echo "FAIL: campaign log has daemon reboots"; grep -a "reboots total=" "$LOG12"
else
  echo "OK: no daemon reboots in campaign log"
fi
if grep -aq "plan_ready fence TIMEOUT" "$LOG12"; then
  echo "FAIL: plan_ready fence timeouts present"; grep -a "plan_ready fence TIMEOUT" "$LOG12" | head -2
else
  echo "OK: no plan_ready fence timeouts"
fi
echo "LOGS: $DIR"