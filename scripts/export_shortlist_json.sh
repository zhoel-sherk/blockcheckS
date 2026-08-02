#!/usr/bin/env bash
# Export blockchecks.shortlist/v1 for GP orchestrator (P5-1).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DB="${1:-state.db}"
OUTPUT="${2:-logs/shortlist.json}"
DOMAINS_FILE="${DOMAINS_FILE:-presets/domains/coverage-tcp.txt}"
python3 -m blockchecks.shortlist_export \
  --db "$DB" \
  --domains-file "$DOMAINS_FILE" \
  -o "$OUTPUT"
