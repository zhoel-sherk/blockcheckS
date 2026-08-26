#!/usr/bin/env bash
# systemd boot-resume launcher for the long-term run series.
# Starts scripts/run_long_term_series.sh ONLY when boot-resume was explicitly
# requested (BS_SERIES_BOOT_RESUME=1 or logs/series.resume sentinel) and the
# series has not finished (no logs/series.COMPLETE). Exits 0 (no-op) otherwise.
# Guarded against double-start: the orchestrator refuses if bs-series already
# exists.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HOURS="${BS_SERIES_HOURS:-20}"
START_VAR="${BS_SERIES_START:-A}"
SERIES_COMPLETE="${BS_SERIES_COMPLETE_SENTINEL:-logs/series.COMPLETE}"
SERIES_RESUME="${BS_SERIES_RESUME_SENTINEL:-logs/series.resume}"

if [ -f "$SERIES_COMPLETE" ]; then
  echo "blockcheckS: series complete ($SERIES_COMPLETE), skipping boot-resume"
  exit 0
fi

if [ "${BS_SERIES_BOOT_RESUME:-0}" != 1 ] && [ ! -f "$SERIES_RESUME" ]; then
  echo "blockcheckS: no boot-resume sentinel ($SERIES_RESUME) and BS_SERIES_BOOT_RESUME!=1, skipping"
  exit 0
fi

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
