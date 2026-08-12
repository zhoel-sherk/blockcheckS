#!/usr/bin/env bash
# Coverage run with NEW families (rst_fake/synack/wssize/geneva_fool) + full
# standard pool (24 209) + flowseal gaps, geneva.lua hooks, data-block sync.
# 20h default. Sequential in the A→F long-term plan.
#
# Usage:
#   scripts/run_coverage_new.sh [hours] [session-name]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source .venv/bin/activate

HOURS="${1:-20}"
SESSION="${TMUX_SESSION:-bs-coverage-new}"
export BLOCKCHECKS_BLOBS="${BLOCKCHECKS_BLOBS:-$ROOT/blobs}"
export BLOCKCHECKS_SETTINGS="${BLOCKCHECKS_SETTINGS:-$ROOT/../dpi-tester/settings.ini}"
# geneva.lua escape-hatch hooks (fool=bs_* Geneva 1-9/22/24)
export BLOCKCHECKS_LUA_EXTRA="${BLOCKCHECKS_LUA_EXTRA:-$ROOT/lua/blockchecks/geneva.lua}"
# Dead/RKN-blocked SOCKS must not stall googlevideo URL fetch (empty = no fallback).
export BLOCKCHECKS_PROXY="${BLOCKCHECKS_PROXY-}"
export PYTHONUNBUFFERED=1
export PATH="$ROOT/.venv/bin:$PATH"

mkdir -p logs/coverage_new_export
TS="$(date +%Y%m%d_%H%M%S)"
LOG="logs/coverage_new_${TS}.log"
echo "$LOG" > logs/coverage_new_LATEST.logpath

for i in 0 1 2 3; do
  sudo ip netns del "bs-p-$i" 2>/dev/null || true
  sudo ip link del "vh-bs-p-$i" 2>/dev/null || true
done
sudo pkill -9 nfqws2 2>/dev/null || true
pkill -9 -f 'bs full --domains-file' 2>/dev/null || true

if tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux kill-session -t "$SESSION"
fi

RUNNER=$(mktemp /tmp/bs_cov_new.XXXXXX.sh)
cat >"$RUNNER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
ulimit -n 65536
ulimit -u 65536 || true
cd "$ROOT"
export PATH="$ROOT/.venv/bin:\$PATH"
export HOME="$HOME"
export BLOCKCHECKS_BLOBS="$BLOCKCHECKS_BLOBS"
export BLOCKCHECKS_SETTINGS="$BLOCKCHECKS_SETTINGS"
export BLOCKCHECKS_PROXY="${BLOCKCHECKS_PROXY-}"
export BLOCKCHECKS_LUA_EXTRA="$BLOCKCHECKS_LUA_EXTRA"
export PYTHONUNBUFFERED=1
exec bs full \\
  --max-timeh $HOURS \\
  --domains-file presets/domains/coverage.txt \\
  --db logs/coverage_new.db \\
  --out-dir logs/coverage_new_export \\
  --parallel 4 \\
  --bridge-batch 10 \\
  --no-wssize \\
  --no-settle-profile \\
  --scan-level full \\
  --max 30000 \\
  --timeout 2 \\
  --allow-dns-hijack \\
  --resume \\
  --data-block-sync \\
  --skip-prolog \\
  --skip-ip-block \\
  --skip-port-block \\
  --isp-interface eth3
EOF
chmod 700 "$RUNNER"

tmux new-session -d -s "$SESSION" -c "$ROOT" bash -lc "
set -o pipefail
source .venv/bin/activate
export BLOCKCHECKS_PROXY=\"\${BLOCKCHECKS_PROXY-}\"
LOG='$LOG'
echo \"=== START \$(date -Is) ulimit_nofile=\$(ulimit -n) proxy=\${BLOCKCHECKS_PROXY:-none} lua_extra=\$BLOCKCHECKS_LUA_EXTRA ===\" | tee -a \"\$LOG\"
sudo -E env BLOCKCHECKS_PROXY=\"\${BLOCKCHECKS_PROXY-}\" \"$RUNNER\" 2>&1 | tee -a \"\$LOG\"
ec=\${PIPESTATUS[0]}
rm -f \"$RUNNER\"
echo \"=== END \$(date -Is) exit=\$ec ===\" | tee -a \"\$LOG\"
exit \$ec
"

echo "started tmux:$SESSION log:$LOG"
echo "attach: tmux attach -t $SESSION"
echo "domains: coverage.txt ($(grep -c . presets/domains/coverage.txt) lines), geneva.lua: $BLOCKCHECKS_LUA_EXTRA"
