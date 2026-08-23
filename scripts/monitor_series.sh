#!/usr/bin/env bash
# Progress + results summary for the long-term run series (A-F) and week coverage.
# Usage: scripts/monitor_series.sh [A|B|C|D|E|F|G|week]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

summarize_db() {
  local dbf="$1"
  [ -n "$dbf" ] && [ -f "$dbf" ] || return 0
  "$ROOT/.venv/bin/python3" - "$dbf" <<'PYEOF'
import sqlite3, sys
db = sys.argv[1]
try:
    con = sqlite3.connect(db); con.execute('PRAGMA wal_checkpoint')
    cur = con.cursor()
    cur.execute("SELECT count(*) FROM tcp_results"); total = cur.fetchone()[0]
    cur.execute("SELECT status, count(*) FROM tcp_results GROUP BY status"); st = cur.fetchall()
    cur.execute("SELECT count(DISTINCT strategy_id) FROM tcp_results"); sids = cur.fetchone()[0]
    cur.execute("SELECT count(DISTINCT domain) FROM tcp_results"); doms = cur.fetchone()[0]
    print(f"  db={db}")
    print(f"  results={total} strategies={sids} domains={doms} statuses={dict(st)}")
    watch = (
        "updates.discord.com",
        "gateway.discord.gg",
        "discord.com",
        "youtube.com",
        "googlevideo.com",
    )
    for d in watch:
        p = cur.execute(
            "SELECT count(*) FROM tcp_results WHERE domain=? AND status='PASS'", (d,)
        ).fetchone()[0]
        t = cur.execute("SELECT count(*) FROM tcp_results WHERE domain=?", (d,)).fetchone()[0]
        if t:
            print(f"  {d}: pass={p}/{t}")
except Exception as e:
    print(f"  db error: {e}")
PYEOF
}

show_variant() {
  local var="$1"
  local latest="$(cat "logs/run_${var}_LATEST.logpath" 2>/dev/null || true)"
  echo "── Variant $var ───────────────────────────────"
  if [ -n "$latest" ] && [ -f "$latest" ]; then
    echo "log: $latest"
    tail -3 "$latest" | grep -E "batch|pass=|PASS|END" | tail -2 || true
  else
    echo "  (not started)"
  fi
  local dbf
  dbf="$(ls logs/run_${var}_*.db 2>/dev/null | head -1 || true)"
  summarize_db "$dbf"
}

show_week() {
  echo "── Week coverage ───────────────────────────────"
  echo "week tmux: $(tmux has-session -t bs-week 2>/dev/null && echo ACTIVE || echo idle)"
  local latest
  latest="$(cat logs/week_cov_LATEST.logpath 2>/dev/null || true)"
  if [ -n "$latest" ] && [ -f "$latest" ]; then
    echo "log: $latest"
    tail -5 "$latest" | grep -E "STAGE|batch|pass=|PASS|END|WEEK" | tail -4 || true
  else
    echo "  (not started)"
  fi
  summarize_db logs/week_cov.db
  if [ -f logs/week_cov_udp.db ]; then
    echo "── Week UDP ────────────────────────────────────"
    summarize_db logs/week_cov_udp.db
  fi
}

if [ $# -ge 1 ]; then
  if [ "$1" = "week" ]; then
    show_week
  else
    show_variant "$1"
  fi
else
  echo "== Long-term series: A B C D E F =="
  echo "series tmux: $(tmux has-session -t bs-series 2>/dev/null && echo ACTIVE || echo idle)"
  for v in A B C D E F; do
    show_variant "$v"
  done
  echo
  show_week
fi
