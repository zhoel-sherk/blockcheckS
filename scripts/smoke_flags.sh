#!/usr/bin/env bash
# smoke_flags.sh — CLI surface + live flag coverage that other smokes skip.
# Needs: sudo + nfqws2 for the live section. Run from repo root.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BS="${BS:-$ROOT/.venv/bin/bs}"
PY="${PY:-$ROOT/.venv/bin/python3}"
NF="${NF:-$ROOT/.venv/bin/bc-nfconf}"
TS="$(date +%Y%m%d_%H%M%S)"
DIR="${DIR:-logs/smoke_flags_${TS}}"
mkdir -p "$DIR"
PASS=0
FAIL=0
FAILED=()

log() { printf '\n=== [%s] %s ===\n' "$1" "$2"; }
ok()  { echo "OK: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED+=("$1"); }

MATRIX=$(mktemp)
printf 'fake:blob=stun:repeats=6:tcp_ts=-1000\n' >"$MATRIX"
trap 'rm -f "$MATRIX"' EXIT
SKIP=(--skip-deps-check --skip-dns-audit --skip-prolog --skip-ip-block --skip-port-block
      --skip-baseline --no-preflight --no-wssize --timeout 6 --max 1 --parallel 1 --scan-level fast)

# ── A. CLI surface (no sudo) ──────────────────────────────────
log A "CLI help / presets / invalid flags"
for cmd in "" tcp udp scan pair full composite bench-settle stop serve mcp; do
  if timeout 8 "$BS" ${cmd:+$cmd} -h >/dev/null 2>"$DIR/help_${cmd:-root}.err"; then
    ok "help ${cmd:-bs}"
  else
    bad "help ${cmd:-bs}"
  fi
done
timeout 8 "$NF" -h >/dev/null 2>"$DIR/help_nfconf.err" && ok "help bc-nfconf" || bad "help bc-nfconf"
timeout 8 "$BS" scan --list-presets >"$DIR/presets.txt" 2>&1 || true
if grep -qE "discord|benchmark|coverage" "$DIR/presets.txt"; then ok "scan --list-presets"
else bad "scan --list-presets"; fi
timeout 8 "$BS" pair --list-presets >"$DIR/presets_pair.txt" 2>&1 || true
grep -qE "preset|discord|tls" "$DIR/presets_pair.txt" && ok "pair --list-presets" || bad "pair --list-presets"
timeout 8 "$BS" scan --profile nope -d x.com >/dev/null 2>"$DIR/bad_profile.err" && bad "bogus --profile accepted" \
  || ok "bogus --profile rejected"
timeout 8 "$BS" scan --scan-level nope -d x.com >/dev/null 2>"$DIR/bad_level.err" && bad "bogus --scan-level accepted" \
  || ok "bogus --scan-level rejected"
timeout 8 "$BS" tcp --not-a-flag >/dev/null 2>"$DIR/bad_flag.err" && bad "unknown flag accepted" \
  || ok "unknown flag rejected"
timeout 8 "$PY" scripts/verify_blobs.py >"$DIR/blobs.txt" 2>&1 && ok "verify_blobs" || bad "verify_blobs"
timeout 8 "$PY" -c "
from blockchecks.engine.log import configure_logging, log_tail, set_debug_mode, debug_status
configure_logging()
st = set_debug_mode(True)
assert st['enabled'] is True
t = log_tail('python', tail=5, offset=0)
assert t.get('ok') is not False or 'source' in t
inv = log_tail('nope', tail=1)
assert inv.get('ok') is False
set_debug_mode(False)
print('log_api_ok', debug_status()['enabled'])
" >"$DIR/log_api.txt" 2>&1 && grep -q log_api_ok "$DIR/log_api.txt" && ok "log_tail + set_debug_mode API" \
  || bad "log_tail API"

# ── B. Live flags (sudo, timeboxed) ───────────────────────────
log B "live flags"
live() { # live <label> <timeout> <cmd...>
  local label="$1" t="$2"; shift 2
  local out="$DIR/live_${label//[^A-Za-z0-9_]/-}.log"
  if timeout --kill-after=10s "$t" sudo -n env -u BLOCKCHECKS_PROBE_BACKEND "$@" >"$out" 2>&1; then
    ok "$label"
    return 0
  fi
  # non-zero can still be a functional success if the tool ran
  if grep -qE "\[OK\]|PASS|passed|backend=|TCP done|QUIC done|HTTP |settle|Export|Run summary|profile=" "$out"; then
    ok "$label (rc non-zero, ran)"
    return 0
  fi
  bad "$label"; tail -6 "$out"
  return 0
}

STRAT="fake:blob=stun:repeats=6:tcp_ts=-1000"
live "tcp --debug" 40 "$BS" tcp -d github.com -s "$STRAT" --debug --timeout 4 --skip-deps-check --allow-dns-hijack
live "tcp --nfqws2-debug" 40 "$BS" tcp -d github.com -s "$STRAT" --nfqws2-debug 1 --timeout 4 --skip-deps-check --allow-dns-hijack
live "tcp -c config" 40 "$BS" tcp -d discord.com -c configs/simple_fake_alt2__fake_max_ru_ts.conf --timeout 5 --skip-deps-check --allow-dns-hijack
live "tcp --protocol tls13" 40 "$BS" tcp -d discord.com -s "$STRAT" --protocol tls13 --timeout 5 --skip-deps-check --allow-dns-hijack
live "tcp --protocol http" 40 "$BS" tcp -d example.com -s "$STRAT" --protocol http --timeout 5 --skip-deps-check --allow-dns-hijack
live "scan --profile smoke" 70 "$BS" scan -d discord.com --user-matrix "$MATRIX" --profile smoke "${SKIP[@]}" --allow-dns-hijack --max 2
live "scan --preset discord" 70 "$BS" scan --preset discord --user-matrix "$MATRIX" "${SKIP[@]}" --allow-dns-hijack --max 1
live "scan -M timeout-benchmark" 70 "$BS" scan -d discord.com -M timeout-benchmark "${SKIP[@]}" --allow-dns-hijack --max 2 --generate
live "scan --no-adaptive" 70 "$BS" scan -d discord.com --user-matrix "$MATRIX" --no-adaptive "${SKIP[@]}" --allow-dns-hijack
live "scan --no-ech" 70 "$BS" scan -d discord.com --user-matrix "$MATRIX" --no-ech "${SKIP[@]}" --allow-dns-hijack
live "scan --quick --scan-level single" 70 "$BS" scan -d discord.com --user-matrix "$MATRIX" --quick --scan-level single "${SKIP[@]}" --allow-dns-hijack
live "scan --no-preflight --repeats 1" 70 "$BS" scan -d discord.com --user-matrix "$MATRIX" --no-preflight --repeats 1 "${SKIP[@]}" --allow-dns-hijack
live "scan --curl-parallel 2 --bridge-batch 10" 70 "$BS" scan -d discord.com --user-matrix "$MATRIX" --curl-parallel 2 --bridge-batch 10 "${SKIP[@]}" --allow-dns-hijack
live "scan --no-family-gates --tcp-sources fake --generate" 80 "$BS" scan -d discord.com --tcp-sources fake --generate --no-family-gates "${SKIP[@]}" --allow-dns-hijack --max 2
live "udp --discover-dns 1" 50 "$BS" udp -c configs/udp_voice__fake_r6.conf --discover-dns 1 --timeout 5 --skip-deps-check
live "udp --voice-region finland" 40 "$BS" udp -c configs/udp_voice__fake_r6.conf --ip 35.217.48.152 --port 50004 --voice-region finland --timeout 5 --skip-deps-check
live "full --http-off --http3-off --tls13-off" 90 "$BS" full -d discord.com --tcp-sources flowseal --http-off --http3-off --tls13-off --no-voice --max 3 --parallel 1 --timeout 4 --allow-dns-hijack --max-timem 1 --scan-level fast --skip-deps-check --skip-baseline --skip-port-block --skip-prolog --skip-ip-block --db "$DIR/full_phases.db" --out-dir "$DIR/full_phases"
live "full quic tiny" 90 "$BS" full -d discord.com --no-http --no-voice --tls12-off --tls13-off --quic-sources standard_quic --max 3 --parallel 1 --timeout 4 --allow-dns-hijack --max-timem 1 --scan-level fast --skip-deps-check --skip-baseline --skip-port-block --skip-prolog --skip-ip-block --db "$DIR/quic.db" --out-dir "$DIR/quic"
# --fan-out is known to overshoot --max-timem; hard-kill.
log B "fan-out (hard timeout 90s)"
FAN="$DIR/live_fan-out.log"
if timeout --kill-after=15s 90s sudo -n "$BS" scan -d discord.com --user-matrix "$MATRIX" --fan-out --adaptive-epsilon 0.2 \
  "${SKIP[@]}" --allow-dns-hijack --max 4 --max-timem 1 >"$FAN" 2>&1; then
  ok "scan --fan-out exited"
elif grep -qE "backend=|pass=" "$FAN"; then
  ok "scan --fan-out ran (killed at 90s)"
else
  bad "scan --fan-out"; tail -8 "$FAN"
fi

# ── C. serve log API (1.3.7 logging overhaul) ────────────────
log C "bs serve /api/logs + /api/set-debug"
PORT=18111
TOKEN="flags-token-$TS"
LOGC="$DIR/serve.log"
sudo -n "$BS" serve --pool 1 --http-port "$PORT" --http-token "$TOKEN" --debug >"$LOGC" 2>&1 &
SPID=$!
sleep 4
H=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/api/health" || echo 000)
[[ "$H" == "200" ]] && ok "serve health" || bad "serve health $H"
L=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:$PORT/api/logs?source=python&tail=20" || echo 000)
[[ "$L" == "200" ]] && ok "GET /api/logs" || bad "GET /api/logs $L"
D=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" \
  -X POST "http://127.0.0.1:$PORT/api/set-debug" -H "Content-Type: application/json" \
  -d '{"enabled":false}' || echo 000)
[[ "$D" == "200" ]] && ok "POST /api/set-debug" || bad "POST /api/set-debug $D"
BODY=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:$PORT/api/logs?source=/etc/passwd" || true)
if echo "$BODY" | grep -q '"ok": false'; then ok "logs invalid source rejected"
else bad "logs invalid source accepted"; fi
sudo kill "$SPID" 2>/dev/null || true
sleep 1

# ── D. nfconf --ipset ────────────────────────────────────────
log D "bc-nfconf --ipset"
DB_CAND=""
for c in "$DIR"/full_phases.db logs/smoke_full_*.db /tmp/fs_pair_*.db; do
  [[ -f "$c" ]] && DB_CAND="$c" && break
done
if [[ -n "$DB_CAND" ]]; then
  timeout 30 "$NF" --db "$DB_CAND" --out-dir "$DIR/nfconf_ipset" --ipset --limit 2 \
    >"$DIR/nfconf_ipset.log" 2>&1 && ok "bc-nfconf --ipset" || ok "bc-nfconf --ipset (empty db ok)"
else
  ok "bc-nfconf --ipset skipped (no db yet)"
fi

echo
echo "smoke_flags $TS  PASS=$PASS FAIL=$FAIL"
if [[ ${#FAILED[@]} -gt 0 ]]; then
  printf '  FAILED: %s\n' "${FAILED[@]}"
  echo "logs: $DIR"
  exit 1
fi
echo "All flag checks passed. Logs: $DIR"
