#!/usr/bin/env bash
# systemd boot-resume launcher for the long-term run series.
# Starts scripts/run_long_term_series.sh ONLY when there is a non-empty
# results DB (i.e. a prior run exists to resume). Exits 0 (no-op) otherwise.
# Guarded against double-start: the orchestrator refuses if bs-series already
# exists.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HOURS="${BS_SERIES_HOURS:-20}"
START_VAR="${BS_SERIES_START:-A}"

# No DB → nothing to resume.
if ! ls logs/run_*.db >/dev/null 2>&1; then
  echo "blockcheckS: no run DB found, skipping series boot-resume"
  exit 0
fi

# DB present but empty (0 tcp_results) → nothing meaningful to resume.
HAS_ROWS=0
for db in logs/run_*.db; do
  N=$("$ROOT/.venv/bin/python3" - "$db" <<'PYEOF'
import sqlite3, sys
try:
    con = sqlite3.connect(sys.argv[1])
    n = con.execute("SELECT count(*) FROM tcp_results").fetchone()[0]
    print(n)
except Exception:
    print(0)
PYEOF
)
  if [ "${N:-0}" -gt 0 ]; then
    HAS_ROWS=1
    break
  fi
done
if [ "$HAS_ROWS" = 0 ]; then
  echo "blockcheckS: run DBs empty, skipping series boot-resume"
  exit 0
fi

echo "blockcheckS: boot-resume series ${START_VAR}→F (${HOURS}h)"
exec scripts/run_long_term_series.sh "$HOURS" "$START_VAR"
