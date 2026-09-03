#!/usr/bin/env bash
# nonsense_user.sh — emulate an operator who did not read the docs.
# Scenarios A–E: argparse, no-sudo, flag soup, fullish sudo -E, sudo without -E.
# Verdicts: PASS / EXPECTED / HOLE. Report: logs/nonsense_*_holes.md
#
# Usage: bash dev/nonsense_user.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BS="${BS:-$ROOT/.venv/bin/bs}"
DOMAINS="$ROOT/presets/domains/nonsense.txt"
TS="$(date +%Y%m%d_%H%M%S)"
LOG="logs/nonsense_${TS}.log"
HOLES="logs/nonsense_${TS}_holes.md"
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/blockcheckS"
mkdir -p logs logs/nonsense_export

if [ -f "$STATE/run.lock" ]; then
  echo "ERROR: $STATE/run.lock present — refuse nonsense_user" >&2
  exit 2
fi

PASS=0
EXPECTED=0
HOLE=0
N=0

cleanup_run() {
  sudo -n "$BS" stop --wait 2 >/dev/null 2>&1 || true
  bash "$ROOT/scripts/cleanup_env.sh" >/dev/null 2>&1 || true
}
trap cleanup_run EXIT

{
  echo "# Nonsense human-usage ${TS}"
  echo
  echo "| id | verdict | rc | note |"
  echo "| --- | --- | --- | --- |"
} >"$HOLES"

report() {
  # report <id> <PASS|EXPECTED|HOLE> <rc> <note>
  local id="$1" v="$2" rc="$3" note="$4"
  N=$((N + 1))
  case "$v" in
    PASS) PASS=$((PASS + 1)) ;;
    EXPECTED) EXPECTED=$((EXPECTED + 1)) ;;
    HOLE) HOLE=$((HOLE + 1)) ;;
  esac
  echo "${v}  ${id}  rc=${rc}  ${note}" | tee -a "$LOG"
  echo "| ${id} | ${v} | ${rc} | ${note} |" >>"$HOLES"
}

run_cap() {
  # run_cap <timeout_sec> — command in "$@" ; sets OUT RC
  local t="$1"
  shift
  set +e
  OUT=$(timeout --foreground --kill-after=15s "${t}s" "$@" 2>&1)
  RC=$?
  set -e
  echo "$OUT" | tee -a "$LOG" >/dev/null
}

echo "=== nonsense_user ${TS} ===" | tee "$LOG"

# ── A argparse / early CLI (no live nfqws2 needed) ───────────
echo "--- A argparse ---" | tee -a "$LOG"

run_cap 8 "$BS" full --max-timeh 1 --max-timem 10 --skip-deps-check
if [ "$RC" -ne 0 ] && grep -qiE "max-timeh|max-timem|only one" <<<"$OUT"; then
  report A_time_flags EXPECTED "$RC" "parser rejects both time limits"
else
  report A_time_flags HOLE "$RC" "both --max-timeh and --max-timem accepted"
fi

run_cap 8 "$BS" full -d youtube.com --domains-file "$DOMAINS" --skip-deps-check \
  --skip-dns-audit --max 1 --tcp-only --parallel 1 --timeout 3 --max-timem 1 \
  --db "/tmp/nonsense_a_dfile_${TS}.db"
if grep -qiE "warning.*-d|ignoring.*--domain|domains-file.*overrides" <<<"$OUT"; then
  report A_d_vs_file PASS "$RC" "-d ignored with warning"
elif grep -qiE "youtube.com" <<<"$OUT" && ! grep -qiE "signal.org|rutracker|torproject" <<<"$OUT"; then
  report A_d_vs_file HOLE "$RC" "-d won over --domains-file"
else
  report A_d_vs_file HOLE "$RC" "--domains-file wins; -d dropped with no warning"
fi

run_cap 8 "$BS" full --preset coverage --domains-file "$DOMAINS" --skip-deps-check \
  --skip-dns-audit --max 1 --tcp-only --parallel 1 --timeout 3 --max-timem 1 \
  --db "/tmp/nonsense_a_preset_${TS}.db"
if grep -qiE "warning.*preset|ignoring.*preset|domains-file.*overrides" <<<"$OUT"; then
  report A_preset_vs_file PASS "$RC" "preset ignored with warning"
else
  report A_preset_vs_file HOLE "$RC" "--domains-file wins; --preset dropped with no warning"
fi

run_cap 8 "$BS" full --classic --skip-deps-check --skip-dns-audit --max 1 --tcp-only \
  --parallel 1 --timeout 3 --max-timem 1 --db "/tmp/nonsense_a_classic_${TS}.db" \
  -d discord.com
if grep -qiE "classic.*deprecat|mapping to lua_bridge" <<<"$OUT" \
  && ! grep -qiE "backend=classic" <<<"$OUT"; then
  report A_classic EXPECTED "$RC" "--classic warned at parse (lua_bridge)"
else
  report A_classic HOLE "$RC" "--classic did not warn or still looks classic"
fi

run_cap 8 "$BS" tcp --skip-deps-check
if [ "$RC" -ne 0 ] && ! grep -qiE "Traceback" <<<"$OUT"; then
  report A_tcp_no_d EXPECTED "$RC" "argparse requires -d"
else
  report A_tcp_no_d HOLE "$RC" "tcp without -d: traceback or rc=0"
fi

EMPTY="/tmp/nonsense_empty_${TS}.txt"
: >"$EMPTY"
run_cap 8 "$BS" full --domains-file "$EMPTY" --skip-deps-check --skip-dns-audit \
  --max 1 --tcp-only --max-timem 1 --db "/tmp/nonsense_a_empty_${TS}.db"
if [ "$RC" -ne 0 ] && grep -qiE "ERROR|no domains|empty" <<<"$OUT"; then
  report A_empty_file EXPECTED "$RC" "empty file rejected"
elif [ "$RC" -eq 124 ]; then
  report A_empty_file HOLE "$RC" "empty file hung/timeout"
else
  report A_empty_file HOLE "$RC" "empty file did not error clearly"
fi

# ── B no sudo ────────────────────────────────────────────────
echo "--- B no sudo ---" | tee -a "$LOG"
ROOT_LOCK="/root/.local/state/blockcheckS/run.lock"
run_cap 90 "$BS" full --domains-file "$DOMAINS" --max 2 --parallel 1 --timeout 3 \
  --db "/tmp/nonsense_b_${TS}.db"
B_NOTE="non-root full"
if [ -f "$ROOT_LOCK" ]; then
  report B_nosudo HOLE "$RC" "wrote /root run.lock"
elif [ "$RC" -eq 124 ]; then
  report B_nosudo HOLE "$RC" "non-root hung until timeout"
elif grep -qiE "passwordless sudo|sudo -n" <<<"$OUT" && [ "$RC" -eq 2 ]; then
  report B_nosudo EXPECTED "$RC" "fail-fast before DNS (no sudo -n)"
elif grep -qiE "Traceback" <<<"$OUT" && ! grep -qiE "sudo|nfqws2|permission|root" <<<"$OUT"; then
  report B_nosudo HOLE "$RC" "traceback without sudo/nfqws2 hint"
elif [ -f "$STATE/run.lock" ]; then
  report B_nosudo HOLE "$RC" "user run.lock left behind"
else
  report B_nosudo EXPECTED "$RC" "exited without hang; XDG still user"
fi

# ── C flag soup (short live) ─────────────────────────────────
echo "--- C flags ---" | tee -a "$LOG"
bash "$ROOT/dev/smoke_host_reset.sh" >/dev/null 2>&1 || true

run_cap 180 sudo -n -E "$BS" full --domains-file "$DOMAINS" --tcp-only --no-http --no-quic \
  --max 2 --parallel 1 --timeout 4 --skip-deps-check \
  --db "/tmp/nonsense_c_tcp_${TS}.db"
if [ "$RC" -eq 124 ]; then
  report C_tcp_only_soup HOLE "$RC" "timeout"
else
  report C_tcp_only_soup PASS "$RC" "tcp-only + no-http/quic ran"
fi

bash "$ROOT/dev/smoke_host_reset.sh" >/dev/null 2>&1 || true
run_cap 180 sudo -n -E "$BS" full -d discord.com --no-adaptive --fan-out \
  --max 2 --parallel 1 --timeout 4 --tcp-only --skip-deps-check \
  --db "/tmp/nonsense_c_aq_${TS}.db"
if [ "$RC" -eq 124 ]; then
  report C_noadapt_fanout HOLE "$RC" "timeout"
else
  report C_noadapt_fanout PASS "$RC" "--no-adaptive --fan-out rc=${RC}"
fi

bash "$ROOT/dev/smoke_host_reset.sh" >/dev/null 2>&1 || true
run_cap 240 sudo -n -E "$BS" full -d discord.com --profile 20h --max-timem 3 \
  --max 2 --parallel 1 --tcp-only --skip-deps-check \
  --db "/tmp/nonsense_c_20h_${TS}.db"
if grep -qiE "20h|profile" <<<"$OUT"; then
  report C_profile_vs_timem PASS "$RC" "profile 20h vs --max-timem 3 logged"
elif [ "$RC" -eq 124 ]; then
  report C_profile_vs_timem HOLE "$RC" "timeout (20h profile ignored time cap?)"
else
  report C_profile_vs_timem PASS "$RC" "exited; check log who won (20h vs 3m)"
fi

# ── D fullish ────────────────────────────────────────────────
echo "--- D fullish ---" | tee -a "$LOG"
bash "$ROOT/dev/smoke_host_reset.sh" >/dev/null 2>&1 || true
set +e
timeout --foreground --kill-after=20s 1980s sudo -n -E "$BS" full \
  --domains-file "$DOMAINS" \
  --profile fast --max 80 --parallel 2 --scan-level fast \
  --max-timem 30 --timeout 4 \
  --db "$ROOT/logs/nonsense.db" --out-dir "$ROOT/logs/nonsense_export" \
  2>&1 | tee -a "$LOG"
RC=${PIPESTATUS[0]}
set -e
OUT=$(tail -80 "$LOG")
if [ "$RC" -eq 124 ]; then
  if grep -qiE "Export configs|Run summary|Done in" <<<"$OUT"; then
    report D_fullish HOLE "$RC" "export/done then hang until timeout"
  else
    report D_fullish HOLE "$RC" "wall timeout before export"
  fi
elif grep -qiE "Export configs|Run summary" <<<"$OUT"; then
  report D_fullish PASS "$RC" "exited after export/summary"
elif [ "$RC" -ne 0 ]; then
  report D_fullish EXPECTED "$RC" "exited with error (junk domains / deps)"
else
  report D_fullish PASS "$RC" "exited 0"
fi

# ── E sudo without -E ────────────────────────────────────────
echo "--- E sudo HOME ---" | tee -a "$LOG"
bash "$ROOT/dev/smoke_host_reset.sh" >/dev/null 2>&1 || true
run_cap 180 sudo "$BS" full -d discord.com --max 1 --tcp-only --max-timem 2 \
  --skip-deps-check --db "/tmp/nonsense_e_${TS}.db"
if [ -f "$ROOT_LOCK" ]; then
  report E_sudo_no_E HOLE "$RC" "run.lock under /root (HOME=/root)"
elif grep -qiE "/root/.local" <<<"$OUT"; then
  report E_sudo_no_E HOLE "$RC" "paths mention /root/.local"
else
  report E_sudo_no_E PASS "$RC" "no /root lock; SUDO_USER XDG likely"
fi

echo "" | tee -a "$LOG"
echo "=== nonsense_user PASS=$PASS EXPECTED=$EXPECTED HOLE=$HOLE log=$LOG ===" | tee -a "$LOG"
echo "" >>"$HOLES"
echo "PASS=$PASS EXPECTED=$EXPECTED HOLE=$HOLE" >>"$HOLES"
echo "log: $LOG" >>"$HOLES"
[ "$HOLE" -eq 0 ] || exit 1
exit 0
