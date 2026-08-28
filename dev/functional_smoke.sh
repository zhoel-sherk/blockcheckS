#!/usr/bin/env bash
# functional_smoke.sh — end-to-end functional test of every `bs` subcommand
# on the live host (sudo + nfqws2 + netns). Run after code changes.
#
# Covers:
#   bs preflight · bs tcp · bs udp · bs composite · bs scan (lua_bridge) ·
#   bs pair (tcp-only) · bs bench-settle · bs full (quick) · bs stop ·
#   bc-nfconf export · shortlist round-trip
#
# Each check asserts the expected output marker; any miss aborts with exit 1.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BS="${BS:-$ROOT/.venv/bin/bs}"
PY="${PY:-$ROOT/.venv/bin/python3}"
TS="$(date +%Y%m%d_%H%M%S)"
LOG="logs/functional_smoke_${TS}.log"
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/blockcheckS"
mkdir -p logs

if [ -f "$STATE/run.lock" ]; then
  echo "ERROR: $STATE/run.lock present — refuse functional_smoke (would reset a live campaign)" >&2
  exit 2
fi

PASS=0
FAIL=0
report() { # report <label> <ok>
  if [ "$2" = "1" ]; then
    echo "PASS  $1" | tee -a "$LOG"
    PASS=$((PASS+1))
  else
    echo "FAIL  $1" | tee -a "$LOG"
    FAIL=$((FAIL+1))
  fi
}

# ── cleanup leftover netns / nfqws2 ──────────────────────────
bash scripts/cleanup_env.sh >/dev/null 2>&1 || true

# ── bs preflight ─────────────────────────────────────────────
echo "--- bs preflight ---" | tee -a "$LOG"
OUT=$(timeout 90 sudo -n "$BS" preflight -d discord.com --quick --skip-deps-check 2>&1 || true)
if echo "$OUT" | grep -qE "Preflight|Triage |triage"; then report "bs preflight" 1; else report "bs preflight" 0; fi

# ── bs tcp ───────────────────────────────────────────────────
echo "--- bs tcp ---" | tee -a "$LOG"
OUT=$(timeout 60 sudo -n "$BS" tcp -d discord.com -s "fake:blob=stun:repeats=6:tcp_ts=-1000" \
  --skip-deps-check 2>&1 || true)
if echo "$OUT" | grep -q "HTTP 200\|passed"; then report "bs tcp single PASS" 1; else report "bs tcp single" 0; fi

# ── bs tcp --ns ──────────────────────────────────────────────
echo "--- bs tcp --ns ---" | tee -a "$LOG"
OUT=$(timeout 90 "$PY" "$ROOT/dev/run_tcp_ns_probe.py" discord.com 2>&1 || true)
echo "$OUT" | tee -a "$LOG" >/dev/null
if echo "$OUT" | grep -q "HTTP 200\|passed"; then report "bs tcp --ns PASS" 1; else report "bs tcp --ns" 0; fi

# ── bs udp ───────────────────────────────────────────────────
echo "--- bs udp ---" | tee -a "$LOG"
OUT=$(timeout 60 sudo -n "$BS" udp -c configs/udp_voice__fake_r6.conf --ip 35.217.5.42 --port 50006 \
  --skip-deps-check 2>&1 || true)
if echo "$OUT" | grep -q "passed"; then report "bs udp voice probe" 1; else report "bs udp" 0; fi

# ── bs composite ─────────────────────────────────────────────
echo "--- bs composite ---" | tee -a "$LOG"
OUT=$(timeout 60 sudo -n "$BS" composite -c configs/composite_discord.conf -d discord.com \
  --skip-deps-check 2>&1 || true)
if echo "$OUT" | grep -q "HTTP 200\|1/1 passed"; then report "bs composite" 1; else report "bs composite" 0; fi
if echo "$OUT" | grep -q 'chmod 0777' && ! echo "$OUT" | grep -qi 'warning'; then
  report "bs composite IPC chmod 0777 without warning" 0
else
  report "bs composite IPC ACL (no silent 0777)" 1
fi

# ── bs scan: lua_bridge ──────────────────────────────────────
echo "--- bs scan (lua_bridge) ---" | tee -a "$LOG"
MATRIX=$(mktemp); trap 'rm -f "$MATRIX"' EXIT
printf 'fake:blob=stun:repeats=6:tcp_ts=-1000\nfake:blob=max_ru:repeats=6:tcp_ts=-1000\n' >"$MATRIX"
OUT=$(timeout 90 sudo -n "$BS" scan -d discord.com --user-matrix "$MATRIX" --max 2 --parallel 1 \
  --scan-level fast --quick --skip-deps-check --skip-dns-audit --skip-prolog \
  --skip-ip-block --skip-port-block --skip-baseline --no-wssize --timeout 8 \
  --db "/tmp/fs_scan_$TS.db" 2>&1 || true)
if echo "$OUT" | grep -q "backend=lua_bridge" && echo "$OUT" | grep -q "passed"; then
  report "bs scan lua_bridge" 1
else
  report "bs scan lua_bridge" 0
fi
if "$PY" "$ROOT/dev/assert_smoke_db.py" --db "/tmp/fs_scan_$TS.db" >/dev/null 2>&1; then
  report "scan harvest APPLIED" 1
else
  report "scan harvest APPLIED" 0
fi

# ── bs pair (tcp-only) ───────────────────────────────────────
echo "--- bs pair --tcp-only ---" | tee -a "$LOG"
OUT=$(timeout 90 sudo -n "$BS" pair -d discord.com --user-matrix "$MATRIX" --tcp-only --max 2 \
  --parallel 1 --scan-level fast --quick --skip-deps-check --skip-dns-audit --skip-prolog \
  --skip-ip-block --skip-port-block --skip-baseline --no-wssize --timeout 8 --db "/tmp/fs_pair_$TS.db" 2>&1 || true)
if echo "$OUT" | grep -q "passed\|TCP discord.com"; then report "bs pair tcp-only" 1; else report "bs pair tcp-only" 0; fi
if "$PY" "$ROOT/dev/assert_smoke_db.py" --db "/tmp/fs_pair_$TS.db" >/dev/null 2>&1; then
  report "pair harvest APPLIED" 1
else
  report "pair harvest APPLIED" 0
fi

# ── bs bench-settle ──────────────────────────────────────────
echo "--- bs bench-settle ---" | tee -a "$LOG"
OUT=$(timeout 120 sudo -n "$BS" bench-settle -d discord.com -s "fake:blob=stun:repeats=6:tcp_ts=-1000" \
  --skip-deps-check --no-write-profile 2>&1 || true)
if echo "$OUT" | grep -q "PASS\|OK\|settle"; then report "bs bench-settle" 1; else report "bs bench-settle" 0; fi

# ── bs full (quick, deadline) ────────────────────────────────
echo "--- bs full quick ---" | tee -a "$LOG"
OUT=$(timeout 120 sudo -n "$BS" full -d discord.com --tcp-sources flowseal --max 2 --parallel 1 \
  --timeout 3 --allow-dns-hijack --max-timem 1 --scan-level fast --quick --no-http \
  --skip-deps-check --skip-baseline --skip-port-block --skip-prolog --skip-ip-block \
  --db "/tmp/fs_full_$TS.db" --out-dir "/tmp/fs_full_$TS" 2>&1 || true)
if echo "$OUT" | grep -q "Export configs\|Run summary\|TCP done"; then report "bs full quick" 1; else report "bs full quick" 0; fi
if "$PY" "$ROOT/dev/assert_smoke_db.py" --db "/tmp/fs_full_$TS.db" >/dev/null 2>&1; then
  report "full harvest APPLIED" 1
else
  report "full harvest APPLIED" 0
fi

# ── quarantine flag (tiny scan) ──────────────────────────────
echo "--- bs scan --no-quarantine ---" | tee -a "$LOG"
OUT=$(timeout 90 sudo -n "$BS" scan -d discord.com --user-matrix "$MATRIX" --max 1 --parallel 1 \
  --scan-level fast --quick --no-quarantine --skip-deps-check --skip-dns-audit --skip-prolog \
  --skip-ip-block --skip-port-block --skip-baseline --no-wssize --timeout 8 \
  --db "/tmp/fs_nq_$TS.db" 2>&1 || true)
if echo "$OUT" | grep -q "backend=lua_bridge"; then report "bs scan --no-quarantine" 1; else report "bs scan --no-quarantine" 0; fi

# ── bs gc dry-run + harvest-batch ────────────────────────────
echo "--- bs gc --db-days ---" | tee -a "$LOG"
OUT=$(timeout 30 "$BS" gc --db-days 14 --db "/tmp/fs_pair_$TS.db" 2>&1 || true)
if echo "$OUT" | grep -qiE "DRY|re-run with --apply|gc db|SKIP|deletes"; then
  report "bs gc --db-days dry-run" 1
else
  report "bs gc --db-days dry-run" 0
fi
echo "--- bs harvest-batch ---" | tee -a "$LOG"
OUT=$(timeout 30 "$BS" harvest-batch --db "/tmp/fs_pair_$TS.db" --min-domains 1 --top 5 \
  --out-dir "/tmp/fs_harvest_$TS" 2>&1 || true)
if echo "$OUT" | grep -qE "harvest →|candidates:|no candidates"; then
  report "bs harvest-batch" 1
else
  report "bs harvest-batch" 0
fi

# ── bs stop (no active run → graceful message) ───────────────
echo "--- bs stop ---" | tee -a "$LOG"
OUT=$(timeout 30 sudo -n "$BS" stop --wait 1 2>&1 || true)
if echo "$OUT" | grep -qi "No active\|Stopped"; then report "bs stop (no-op)" 1; else report "bs stop" 0; fi

# ── bc-nfconf export ─────────────────────────────────────────
echo "--- bc-nfconf export ---" | tee -a "$LOG"
OUT=$(timeout 60 "${ROOT}/.venv/bin/bc-nfconf" --db "/tmp/fs_pair_$TS.db" -d discord.com \
  --out-dir "/tmp/fs_nfconf_$TS" --limit 3 2>&1 || true)
if echo "$OUT" | grep -q "keenetic\|nfqws2_"; then report "bc-nfconf export" 1; else report "bc-nfconf export" 0; fi

# ── bs data-block export ────────────────────────────────────
echo "--- bs data-block export ---" | tee -a "$LOG"
OUT=$(timeout 30 "$BS" data-block --out "/tmp/fs_datablock_$TS" 2>&1 || true)
if echo "$OUT" | grep -q "export complete"; then report "bs data-block export" 1; else report "bs data-block export" 0; fi
rm -rf "/tmp/fs_datablock_$TS"

# ── shortlist export → import round-trip ─────────────────────
echo "--- shortlist round-trip ---" | tee -a "$LOG"
SL="/tmp/fs_shortlist_$TS.json"
SL_OUT="/tmp/fs_import_$TS"
OUT=$(timeout 60 "$PY" -m blockchecks.shortlist_export --db "/tmp/fs_pair_$TS.db" -o "$SL" 2>&1 || true)
if echo "$OUT" | grep -q "Wrote\|shortlist"; then
  OUT2=$(timeout 60 "$PY" -m blockchecks.shortlist_import -i "$SL" --out-dir "$SL_OUT" --prefix fs 2>&1 || true)
  if echo "$OUT2" | grep -qi "Imported"; then report "shortlist round-trip" 1; else report "shortlist round-trip" 0; fi
else
  report "shortlist round-trip" 0
fi

echo ""
echo "=== functional smoke: PASS=$PASS FAIL=$FAIL (log: $LOG) ==="
[ "$FAIL" -eq 0 ] || exit 1
