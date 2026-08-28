#!/usr/bin/env bash
# smoke_full_quick.sh — time-boxed bs full: verifies TCP phase, graceful
# deadline stop, export (nfqws2_*.conf, user.list) and run_summary JSON.
#
# Usage:
#   bash dev/smoke_full_quick.sh [domain] [max-strategies]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BS="${BS:-$ROOT/.venv/bin/bs}"
DOMAIN="${1:-discord.com}"
MAX="${2:-3}"
TS="$(date +%Y%m%d_%H%M%S)"
LOG="logs/smoke_full_${TS}.log"
OUT="logs/smoke_full_${TS}_export"
DB="logs/smoke_full_${TS}.db"
mkdir -p logs "$OUT"

cleanup_run() {
  sudo -n "$BS" stop --wait 2 >/dev/null 2>&1 || true
  bash "$ROOT/scripts/cleanup_env.sh" >/dev/null 2>&1 || true
}
trap cleanup_run EXIT

STATE="${XDG_STATE_HOME:-$HOME/.local/state}/blockcheckS"
if [ -f "$STATE/run.lock" ]; then
  echo "ERROR: $STATE/run.lock present — refuse smoke_full_quick during a live campaign" >&2
  exit 2
fi

echo "=== smoke_full_quick domain=$DOMAIN max=$MAX $(date -Is) ===" | tee "$LOG"
sudo -n "$BS" full \
  -d "$DOMAIN" \
  --tcp-sources flowseal \
  --max "$MAX" --parallel 2 --timeout 4 \
  --allow-dns-hijack --max-timem 1 \
  --scan-level fast --quick \
  --skip-deps-check --skip-baseline --skip-port-block \
  --skip-prolog --skip-ip-block \
  --no-http \
  --db "$DB" --out-dir "$OUT" \
  2>&1 | tee -a "$LOG"

echo "=== artifacts ==="
ls -la "$OUT"/ 2>/dev/null | grep -E "nfqws2|user.list|run_summary" || echo "NO EXPORT"
echo "=== summary ==="
cat "$OUT"/run_summary_*.json 2>/dev/null || echo "no run_summary"
echo "=== log: $LOG ==="
"$ROOT/.venv/bin/python3" "$ROOT/dev/assert_smoke_db.py" --db "$DB" --log "$LOG" --require-backend
