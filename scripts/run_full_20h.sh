#!/usr/bin/env bash
# Launch time-boxed bs full (default 20h) in tmux with safe nofile limits.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source .venv/bin/activate

HOURS="${1:-20}"
SESSION="${TMUX_SESSION:-bs-full-20h}"
export BLOCKCHECKS_BLOBS="${BLOCKCHECKS_BLOBS:-$ROOT/blobs}"
export BLOCKCHECKS_SETTINGS="${BLOCKCHECKS_SETTINGS:-$ROOT/../dpi-tester/settings.ini}"
export PYTHONUNBUFFERED=1
export PATH="$ROOT/.venv/bin:$PATH"

mkdir -p logs/full_20h_export
TS="$(date +%Y%m%d_%H%M%S)"
LOG="logs/full_20h_${TS}.log"
echo "$LOG" > logs/full_20h_LATEST.logpath

for i in 0 1 2 3; do
  sudo ip netns del "bs-p-$i" 2>/dev/null || true
  sudo ip link del "vh-bs-p-$i" 2>/dev/null || true
done
sudo pkill -9 nfqws2 2>/dev/null || true
pkill -9 -f 'bs full --max-timeh' 2>/dev/null || true

if tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux kill-session -t "$SESSION"
fi

# Write inner runner so sudo quoting stays simple.
RUNNER=$(mktemp /tmp/bs_full_20h.XXXXXX.sh)
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
export PYTHONUNBUFFERED=1
exec bs full \\
  --max-timeh $HOURS \\
  --db logs/full_20h.db \\
  --out-dir logs/full_20h_export \\
  --parallel 4 \\
  --fan-out \\
  --allow-dns-hijack \\
  --resume \\
  --skip-prolog \\
  --isp-interface eth3
EOF
chmod 700 "$RUNNER"

tmux new-session -d -s "$SESSION" -c "$ROOT" bash -lc "
set -o pipefail
source .venv/bin/activate
LOG='$LOG'
echo \"=== START \$(date -Is) ulimit_nofile=\$(ulimit -n) ===\" | tee -a \"\$LOG\"
sudo -E \"$RUNNER\" 2>&1 | tee -a \"\$LOG\"
ec=\${PIPESTATUS[0]}
rm -f \"$RUNNER\"
echo \"=== END \$(date -Is) exit=\$ec ===\" | tee -a \"\$LOG\"
exit \$ec
"

echo "started tmux:$SESSION log:$LOG"
echo "attach: tmux attach -t $SESSION"
