#!/usr/bin/env bash
# Progress + results summary for the long-term run series (A-F).
# Usage: scripts/monitor_series.sh [variant]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

show_variant() {
  local var="$1"
  local db="logs/run_${var}_*.db"
  local latest="$(cat "logs/run_${var}_LATEST.logpath" 2>/dev/null || true)"
  echo "── Variant $var ───────────────────────────────"
  if [ -n "$latest" ] && [ -f "$latest" ]; then
    echo "log: $latest"
    tail -3 "$latest" | grep -E "batch|pass=|PASS|END" | tail -2 || true
  else
    echo "  (not started)"
  fi
  # DB summary
  local dbf="$(ls logs/run_${var}_*.db 2>/dev/null | head -1 || true)"
  if [ -n "$dbf" ]; then
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
except Exception as e:
    print(f"  db error: {e}")
PYEOF
  fi
}

if [ $# -ge 1 ]; then
  show_variant "$1"
else
  echo "== Long-term series: A B C D E F =="
  echo "series tmux: $(tmux has-session -t bs-series 2>/dev/null && echo ACTIVE || echo idle)"
  for v in A B C D E F; do
    show_variant "$v"
  done
fi
