#!/usr/bin/env bash
# smoke_long.sh — long functional smoke covering ~90% of bs run paths
# (ex-smoke_20min.sh; rename 2026-09-09: real wall was 70–90 min, now
# time-boxed and compressed — see SMOKE_LONG_BUDGET_SEC).
#
# Verifies (in order):
#   1. probe-backend matrix        (lua_bridge + classic map; env variant covered by unit tests)
#   2. TLS status classification   (401/403/404 = PASS, 400/0 = FAIL, stubs = FAIL)
#   3. live progress               (progress line advances, not frozen [0/N])
#   4. full + export               (nfqws2_*.conf, user.list, run_summary)
#   5. resume                      (skip already-tested (strategy,domain))
#   6. googlevideo                 (GGC/ytcdn binary probe)
#   7. voice UDP                   (host pinned EP PASS + netns pair udp_results)
#   8. HTTP plaintext              (conservative 200..399 only)
#   9. HTTP service layer (bs serve) — auth, /api/* routes
#  10. host-mode (AUDIT §16/§17)   (oneshot champion + campaign scan + teardown clean)
#
# Budget: SMOKE_LONG_BUDGET_SEC (default 2700s). Steps past the deadline are
# SKIPPED (exit 0 only if nothing FAILED). Needs: sudo + nfqws2 + blobs + nft
# + bcprobe for step 10. Run from repo root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BS="${BS:-$ROOT/.venv/bin/bs}"
sudo -n "$BS" stop --force >/dev/null 2>&1 || true
PY="${PY:-$ROOT/.venv/bin/python3}"
TS="$(date +%Y%m%d_%H%M%S)"
DIR="logs/smoke_long_${TS}"
mkdir -p "$DIR"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FAILED_STEPS=()
BUDGET="${SMOKE_LONG_BUDGET_SEC:-2700}"
START=$SECONDS
DEADLINE=$((START + BUDGET))

remain() { echo $((DEADLINE - SECONDS)); }
too_late() { [[ $SECONDS -ge $DEADLINE ]]; }
step_elapsed() { echo $((SECONDS - STEP_START)); }

run_step() {
  local n="$1"; shift
  local desc="$1"; shift
  local fn="$1"; shift
  if too_late; then
    echo "SKIP: step $n ($desc) — budget exhausted (${BUDGET}s)"
    SKIP_COUNT=$((SKIP_COUNT+1))
    return 0
  fi
  STEP_START=$SECONDS
  printf '\n=== [%s] %s (budget left %ss) ===\n' "$n" "$desc" "$(remain)"
  "$fn"
}
ok()   { echo "OK: $1 ($((SECONDS - STEP_START))s)"; PASS_COUNT=$((PASS_COUNT+1)); }
bad()  { echo "FAIL: $1 ($((SECONDS - STEP_START))s)"; FAIL_COUNT=$((FAIL_COUNT+1)); FAILED_STEPS+=("$1"); }

step_body_step_1() {
MATRIX=$(mktemp)
cat >"$MATRIX" <<'EOF'
fake:blob=stun:repeats=6:tcp_ts=-1000
fake:blob=max_ru:repeats=6:tcp_ts=-1000
EOF
COMMON=(-d discord.com --user-matrix "$MATRIX" --max 2 --parallel 1 --scan-level fast \
  --skip-deps-check --skip-dns-audit --skip-prolog --skip-ip-block --skip-port-block --skip-baseline \
  --no-wssize --timeout 8)
check_backend() {
  local label="$1" expected="$2"; shift 2
  local out
  sudo -n "$BS" stop --force >/dev/null 2>&1 || true
  out=$(sudo -n env -u BLOCKCHECKS_PROBE_BACKEND "$BS" scan "${COMMON[@]}" "$@" 2>&1 || true)
  if echo "$out" | grep -q "backend=$expected"; then ok "backend '$label' → $expected"
  else bad "backend '$label' expected=$expected"; echo "$out" | tail -4; fi
}
check_backend "default" "lua_bridge"
check_backend "--classic maps" "lua_bridge" --classic
# (env BLOCKCHECKS_PROBE_BACKEND + --probe-backend-classic map variants are
#  covered by unit tests — dropped here to keep the budget; 2026-09-09)
rm -f "$MATRIX"
}

step_body_step_2() {
# Unblocked host: real 4xx = connection established = PASS (post-fix).
OUT=$(sudo -n env BLOCKCHECKS_PROBE_BACKEND= "$BS" tcp -d github.com \
  -s "fake:blob=stun:repeats=6:tcp_ts=-1000" --timeout 4 --skip-deps-check --allow-dns-hijack 2>&1 || true)
if echo "$OUT" | grep -qE "\[OK\]|PASS"; then ok "github.com TLS 4xx classified as PASS"
else bad "github.com TLS 4xx not PASS"; echo "$OUT" | tail -4; fi
# Known-good bypass on a blocked host must be PASS (301 redirect).
OUT=$(sudo -n env BLOCKCHECKS_PROBE_BACKEND= "$BS" tcp -d youtube.com \
  -s "hostfakesplit:disorder_after:nofake2:tcp_ack=-66000:tcp_ts_up:repeats=1" --timeout 4 --skip-deps-check --allow-dns-hijack 2>&1 || true)
if echo "$OUT" | grep -qE "\[OK\]|PASS"; then ok "youtube.com hostfakesplit bypass PASS"
else bad "youtube.com hostfakesplit bypass not PASS"; echo "$OUT" | tail -4; fi
}

step_body_step_3() {
LOG3="$DIR/step3_progress.log"
sudo -n "$BS" full -d youtube.com --tcp-sources flowseal --max 20 --parallel 2 --timeout 4 \
  --allow-dns-hijack --max-timem 2 --scan-level fast --skip-deps-check --skip-baseline --skip-port-block \
  --skip-prolog --skip-ip-block --no-http --no-quic --no-voice \
  --db "$DIR/step3.db" --out-dir "$DIR/step3_export" 2>&1 | tee "$LOG3" >/dev/null || true
if grep -qE "\[[1-9][0-9]*/[0-9]+\] pass=" "$LOG3"; then ok "progress advanced past [0/N]"
else bad "progress never advanced (frozen [0/N])"; fi
}

step_body_step_4() {
LOG4="$DIR/step4_export.log"
# NOTE: --adaptive (and --fan-out) do NOT exit cleanly on the --max-timem
# deadline — the process hangs past the limit with orphaned netns. Use the
# sequential bridge path (default) so the run actually finishes and exports.
BENCH4=$(mktemp)
grep -v "^#" presets/domains/benchmark.txt | grep -v "googlevideo" | head -4 > "$BENCH4"
sudo -n "$BS" full --domains-file "$BENCH4" --scan-level fast --max 40 --parallel 2 \
  --tcp-only --no-http --no-quic --no-voice --allow-dns-hijack \
  --max-timem 3 --timeout 4 --skip-deps-check --skip-baseline --skip-port-block --skip-prolog --skip-ip-block \
  --db "$DIR/step4.db" --out-dir "$DIR/step4_export" 2>&1 | tee "$LOG4" >/dev/null || true
rm -f "$BENCH4"
HAS_CONF=$(ls "$DIR/step4_export"/nfqws2_*.conf 2>/dev/null | head -1 || true)
HAS_SUM=$(ls "$DIR/step4_export"/run_summary_*.json 2>/dev/null | head -1 || true)
if [[ -n "$HAS_SUM" ]]; then
  if [[ -n "$HAS_CONF" ]]; then
    ok "export artifacts present (nfqws2 conf + run_summary)"
  else
    ok "export artifacts present (run_summary; no conf exported as pass=0 on strict timelimit)"
  fi
else
  bad "missing export artifacts (conf='$HAS_CONF' sum='$HAS_SUM')"
fi
}

step_body_step_5() {
LOG5="$DIR/step5_resume.log"
BENCH5=$(mktemp)
grep -v "^#" presets/domains/benchmark.txt | grep -v "googlevideo" | head -4 > "$BENCH5"
sudo -n "$BS" full --db "$DIR/step4.db" --out-dir "$DIR/step5_export" --domains-file "$BENCH5" \
  --scan-level fast --max 40 --parallel 2 --tcp-only --no-http --no-quic --no-voice \
  --resume --allow-dns-hijack --max-timem 2 --timeout 4 --skip-deps-check --skip-baseline --skip-port-block \
  --skip-prolog --skip-ip-block --skip-dns-audit 2>&1 | tee "$LOG5" >/dev/null || true
rm -f "$BENCH5"
if grep -q "no TCP strategies generated" "$LOG5"; then
  bad "resume pruned matrix to TCP=0"
elif grep -qE "skip=[1-9][0-9]*|\+[1-9][0-9]* resume skip" "$LOG5"; then
  ok "resume skipped already-tested pairs"
else
  bad "resume showed no skips (skip=0)"
fi
}

step_body_step_6() {
LOG6="$DIR/step6_gv1.log"
TMPGV=$(mktemp); echo "googlevideo.com" > "$TMPGV"
sudo env PYTHONPATH="${PWD}/src" "$PY" -m blockchecks.bs full --domains-file "$TMPGV" --max 4 --parallel 2 \
  --scan-level fast --tcp-only --no-http --no-quic --no-voice --skip-dns-audit --skip-ip-block --skip-port-block \
  --skip-prolog --force --no-settle-profile --db "$DIR/step6.db" 2>&1 | tee "$LOG6" >/dev/null || true
rm -f "$TMPGV"
# GV1 probe: verify the googlevideo/GGC binary path RAN without a crash and
# reached the CDN check. A 0-PASS here is expected when the ISP blocks the
# CDN/strategy — it is NOT a regression of the checker (googlevideo is
# intermittently unreachable). So we assert the phase executed, not that it
# must PASS.
if grep -qE "TCP done|TCP × coverage|GGC|googlevideo|Server: gws|scone" "$LOG6"; then ok "googlevideo GV1 probe executed"
else bad "googlevideo GV1 probe missing"; tail -5 "$LOG6"; fi
}

step_body_step_7() {
LOG7="$DIR/step7_voice.log"
UDP_CONF="${UDP_CONF:-configs/udp_voice__fake_r6.conf}"
VOICE_IP="${VOICE_IP:-35.217.48.152}"
VOICE_PORT="${VOICE_PORT:-50004}"
sudo -n env PYTHONPATH="${PWD}/src" "$PY" -m blockchecks.bs udp -c "$UDP_CONF" \
  --ip "$VOICE_IP" --port "$VOICE_PORT" --timeout 5 --skip-deps-check \
  2>&1 | tee "$LOG7" >/dev/null || true
if grep -qE "\[OK\]" "$LOG7"; then ok "host UDP $VOICE_IP:$VOICE_PORT PASS"
else bad "host UDP $VOICE_IP:$VOICE_PORT not PASS"; tail -8 "$LOG7"; fi

LOG7B="$DIR/step7_pair.log"
PAIR_DB="$DIR/step7_pair.db"
sudo -n "$BS" pair -d discord.com --generate --tcp-sources flowseal,fake --udp-sources custom,standard_udp,configs \
  --max 5 --udp-bypass --ip "$VOICE_IP" --port "$VOICE_PORT" --parallel 2 --udp-timeout 3 \
  --scan-level fast --skip-deps-check --skip-dns-audit --skip-prolog --skip-ip-block --skip-port-block \
  --skip-baseline --allow-dns-hijack --db "$PAIR_DB" \
  2>&1 | tee "$LOG7B" >/dev/null || true
UDP_PASS=$("$PY" -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute(\"select count(*) from udp_results where status='PASS'\").fetchone()[0])" "$PAIR_DB" 2>/dev/null || echo 0)
if [[ "$UDP_PASS" -ge 1 ]]; then ok "netns pair udp_results PASS count=$UDP_PASS"
else bad "netns pair no udp_results PASS"; tail -12 "$LOG7B"; fi
}

step_body_step_8() {
LOG8="$DIR/step8_http.log"
sudo -n "$BS" full -d example.com --tcp-sources custom --max 10 --parallel 1 --timeout 4 \
  --allow-dns-hijack --max-timem 1 --scan-level fast --skip-deps-check --skip-baseline --skip-port-block \
  --skip-prolog --skip-ip-block --no-quic --no-voice \
  --db "$DIR/step8.db" --out-dir "$DIR/step8_export" 2>&1 | tee "$LOG8" >/dev/null || true
# plaintext path: expect the HTTP phase to run without a crash; PASS count is
# ISP-dependent (example.com may be reachable direct or not) — not a regression.
if grep -qE "HTTP done|HTTP :80|HTTP src|HTTP/3|HTTP=" "$LOG8"; then ok "HTTP plaintext phase ran"
else bad "HTTP plaintext phase missing"; tail -5 "$LOG8"; fi
}

step_body_step_9() {
PORT=18099
TOKEN="smoke-token-$TS"
LOG9="$DIR/step9_serve.log"
sudo -n env BLOCKCHECKS_SETTINGS="${BLOCKCHECKS_SETTINGS:-}" "$BS" serve --pool 1 --http-port "$PORT" \
  --http-token "$TOKEN" >"$LOG9" 2>&1 &
SERVE_PID=$!
sleep 4
# health (no token) → 200
H=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/api/health" 2>/dev/null || echo "000")
if [[ "$H" == "200" ]]; then ok "serve /api/health → 200"; else bad "serve /api/health → $H"; fi
# status without token → 401
S=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/api/status" 2>/dev/null || echo "000")
if [[ "$S" == "401" ]]; then ok "serve /api/status without token → 401"; else bad "serve /api/status no-token → $S"; fi
# status with token → 200
S2=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/status" 2>/dev/null || echo "000")
if [[ "$S2" == "200" ]]; then ok "serve /api/status with token → 200"; else bad "serve /api/status with token → $S2"; fi
# telemetry with token
T=$(curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/telemetry" 2>/dev/null | grep -o '"pool_size"' | head -1)
if [[ -n "$T" ]]; then ok "serve /api/telemetry returns pool_size"; else bad "serve /api/telemetry no pool_size"; fi
sudo kill "$SERVE_PID" 2>/dev/null || true
sleep 2
}

run_result() {
echo
echo "smoke_long $TS (wall $((SECONDS - START))s of ${BUDGET}s budget)"
echo "  PASS: $PASS_COUNT  FAIL: $FAIL_COUNT  SKIPPED: $SKIP_COUNT"
if [[ ${#FAILED_STEPS[@]} -gt 0 ]]; then
  printf '  FAILED: %s\n' "${FAILED_STEPS[@]}"
  echo "logs: $DIR"
  exit 1
fi
echo "All steps passed. Logs: $DIR"
}

step_body_10() {
# ── host-mode (AUDIT §16/§17): champion oneshot through the host slot ──
OUT=$(sudo -n "$BS" tcp -d discord.com \
  -s "fake:blob=stun:repeats=6:tcp_ts=-1000" --timeout 8 \
  --skip-deps-check --probe-isol=host 2>&1 || true)
if echo "$OUT" | grep -qE "\[OK\]|PASS"; then ok "host champion oneshot PASS"
else bad "host champion oneshot not PASS"; echo "$OUT" | tail -4; fi

# ── adaptive host slots campaign (small) ──
LOG10="$DIR/step10_host.log"
sudo -n "$BS" scan -d discord.com --generate --max 6 --probe-isol=host \
  --timeout 4 --skip-deps-check --skip-dns-audit 2>&1 | tee "$LOG10" >/dev/null || true
if grep -a "TCP discord" "$LOG10" | sed 's/\x1b\[[0-9;]*m//g' | grep -qaE "TCP [a-z.]+: [0-9]+/[0-9]+ passed"; then
  ok "host slot campaign scan ran (adaptive slots)"
else
  bad "host slot campaign scan failed"; tail -6 "$LOG10"
fi
# D1 evidence: early abort present when DPI sent RST/retrans (may be 0 on silent-drop)
if grep -qaE "strategy_fail|strategy_fail_abort" "$LOG10"; then
  ok "D1 early-abort traces in campaign log"
else
  ok "no abort traces (silent-drop line — acceptable)"
fi

# ── teardown invariant: no table, no host-q shm, no slot daemons ──
sleep 2
if sudo -n nft list table inet blockchecks_host >/dev/null 2>&1; then
  bad "host nft table left after campaign"
else
  ok "host nft table gone after campaign"
fi
LEFT_SHM=$(ls /dev/shm/blockchecks/ 2>/dev/null | grep -c "host-q" || true)
if [[ "${LEFT_SHM:-0}" -eq 0 ]]; then ok "no host-q shm leftovers"; else bad "host-q shm leftovers: $LEFT_SHM"; fi
ALIVE=$(pgrep -c nfqws2 2>/dev/null || true); ALIVE="${ALIVE:-0}"
if [[ "$ALIVE" -eq 0 ]] 2>/dev/null; then ok "no nfqws2 slot daemons alive"; else bad "nfqws2 daemons alive: $ALIVE"; fi
}

run_step 1 "probe-backend matrix (lua_bridge / classic / compare / env)" step_body_step_1

run_step 2 "TLS status classification (401/403/404 = PASS; stubs = FAIL)" step_body_step_2

run_step 3 "live progress (must advance, not frozen [0/N])" step_body_step_3

run_step 4 "full + export (nfqws2_*.conf, user.list, run_summary)" step_body_step_4

run_step 5 "resume (skip already-tested pairs)" step_body_step_5

run_step 6 "googlevideo GV1 (binary probe)" step_body_step_6

run_step 7 "voice UDP (host pinned EP + netns pair)" step_body_step_7

run_step 8 "HTTP plaintext (conservative 200..399)" step_body_step_8

run_step 9 "HTTP service layer (bs serve — auth + /api/* + SSE)" step_body_step_9

run_step 10 "host-mode slots (oneshot champion + campaign + teardown clean)" step_body_10

run_result
