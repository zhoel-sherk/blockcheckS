#!/usr/bin/env bash
# B5: export BS shortlist from state.db → nfqws2 keenetic/raw configs
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PWD}/.venv/bin/python"
DB="${1:-state.db}"
DOMAIN="${2:-discord.com}"
OUT="${3:-output/shortlist}"
mkdir -p "$OUT"
PYTHONPATH=src "$PY" -m blockchecks.nfconf \
  --db "$DB" \
  --domain "$DOMAIN" \
  --out-dir "$OUT" \
  --limit 5
echo "Exported to $OUT/"
