#!/usr/bin/env bash
# Between-campaign host reset for smokes. Refuses if run.lock exists.
# Full cleanup_env (host nfqws2) — never use during week_cov.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/blockcheckS"
BS="${BS:-$ROOT/.venv/bin/bs}"
if [ -f "$STATE/run.lock" ]; then
  echo "ERROR: $STATE/run.lock present — refuse smoke_host_reset" >&2
  exit 2
fi
sudo -n "$BS" stop --wait 2 >/dev/null 2>&1 || true
bash "$ROOT/scripts/cleanup_env.sh" >/dev/null 2>&1 || true
