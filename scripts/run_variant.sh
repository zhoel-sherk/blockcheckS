#!/usr/bin/env bash
# Long-term coverage run variants (20h each). Sequential A→F plan; G is
# Discord-voice UDP (bs pair) and is launched separately — not in A→F.
# Variant config map:
#   A  base          coverage.txt, bridge-batch 10, timeout 2, lua-bridge
#   B  new           coverage.txt, full pool 30000, timeout 2, geneva.lua
#   C  adaptive      base + --fan-out --adaptive (genetics boost)
#   D  classic       base + --classic (no lua-bridge backend)
#   E  flowseal      coverage.txt, --tcp-sources flowseal
#   F  stable        base + --repeats 3 --repeats-mode stable
#   G  udp_voice     bs pair Discord-UDP, 35.217, full generate_udp, loop to 20h
#
# Usage: scripts/run_variant.sh {A|B|C|D|E|F|G} [hours]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source .venv/bin/activate

VAR="${1:?usage: run_variant.sh A|B|C|D|E|F|G [hours]}"
HOURS="${2:-20}"
KIND="full"
DOMAINS="presets/domains/coverage.txt"

case "$VAR" in
  A)
    SESSION="bs-run-A"
    DB="logs/run_A_base.db"
    OUT="logs/run_A_base_export"
    EXTRA="--bridge-batch 10 --no-wssize --no-settle-profile --timeout 2 --adaptive --adaptive-epsilon 0.1"
    ;;
  B)
    SESSION="bs-run-B"
    DB="logs/run_B_new.db"
    OUT="logs/run_B_new_export"
    EXTRA="--bridge-batch 10 --no-wssize --no-settle-profile --scan-level full --max 30000 --timeout 2"
    export BLOCKCHECKS_LUA_EXTRA="${BLOCKCHECKS_LUA_EXTRA:-$ROOT/lua/blockchecks/geneva.lua}"
    ;;
  C)
    SESSION="bs-run-C"
    DB="logs/run_C_adaptive.db"
    OUT="logs/run_C_adaptive_export"
    EXTRA="--bridge-batch 10 --no-wssize --no-settle-profile --timeout 2 --fan-out --adaptive --adaptive-epsilon 0.1"
    ;;
  D)
    SESSION="bs-run-D"
    DB="logs/run_D_classic.db"
    OUT="logs/run_D_classic_export"
    EXTRA="--bridge-batch 10 --no-wssize --no-settle-profile --timeout 2 --classic"
    ;;
  E)
    SESSION="bs-run-E"
    DB="logs/run_E_flowseal.db"
    OUT="logs/run_E_flowseal_export"
    EXTRA="--bridge-batch 10 --no-wssize --no-settle-profile --timeout 2 --tcp-sources flowseal"
    ;;
  F)
    SESSION="bs-run-F"
    DB="logs/run_F_stable.db"
    OUT="logs/run_F_stable_export"
    EXTRA="--bridge-batch 10 --no-wssize --no-settle-profile --timeout 2 --repeats 3 --repeats-mode stable"
    ;;
  G)
    SESSION="bs-run-G"
    DB="logs/run_G_udp_voice.db"
    OUT="logs/run_G_udp_voice_export"
    KIND="pair"
    DOMAINS=""
    EXTRA=""
    ;;
  *)
    echo "unknown variant: $VAR (A|B|C|D|E|F|G)" >&2
    exit 2
    ;;
esac

export BLOCKCHECKS_BLOBS="${BLOCKCHECKS_BLOBS:-$ROOT/blobs}"
export BLOCKCHECKS_SETTINGS="${BLOCKCHECKS_SETTINGS:-$ROOT/../dpi-tester/settings.ini}"
export BLOCKCHECKS_PROXY="${BLOCKCHECKS_PROXY-}"
export BLOCKCHECKS_LUA_EXTRA="${BLOCKCHECKS_LUA_EXTRA-}"
export PYTHONUNBUFFERED=1
export PATH="$ROOT/.venv/bin:$PATH"

mkdir -p "$OUT"
TS="$(date +%Y%m%d_%H%M%S)"
LOG="logs/run_${VAR}_${TS}.log"
echo "$LOG" > "logs/run_${VAR}_LATEST.logpath"

for i in 0 1 2 3; do
  sudo ip netns del "bs-p-$i" 2>/dev/null || true
  sudo ip link del "vh-bs-p-$i" 2>/dev/null || true
done
sudo pkill -9 nfqws2 2>/dev/null || true
pkill -9 -f 'bs full --domains-file' 2>/dev/null || true

if tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux kill-session -t "$SESSION"
fi

RUNNER=$(mktemp /tmp/bs_run_${VAR}.XXXXXX.sh)
if [ "$KIND" = "pair" ]; then
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
export BLOCKCHECKS_LUA_EXTRA="${BLOCKCHECKS_LUA_EXTRA-}"
export PYTHONUNBUFFERED=1
END=\$(( \$(date +%s) + ${HOURS} * 3600 ))
echo "=== G loop until \$(date -d @\$END -Is 2>/dev/null || date -Is) ==="
while true; do
  NOW=\$(date +%s)
  REMAIN=\$(( END - NOW ))
  if [ "\$REMAIN" -lt 90 ]; then
    echo "=== G time budget exhausted remain=\$REMAIN ==="
    break
  fi
  if [ "\$REMAIN" -ge 3600 ]; then
    TF=(--max-timeh "\$(python3 -c "print(\$REMAIN/3600.0)")")
  else
    TF=(--max-timem "\$(python3 -c "print(\$REMAIN/60.0)")")
  fi
  echo "=== G wave remain=\${REMAIN}s \${TF[*]} \$(date -Is) ==="
  bs pair -d discord.com --generate \\
    --tcp-sources fake \\
    --udp-sources custom,standard_udp,configs,flowseal \\
    --scan-level full --max 200 --udp-bypass \\
    --ip 35.217.48.152 --port 50004 --discover-dns 5 \\
    --parallel 2 --timeout 3 --udp-timeout 3 \\
    --allow-dns-hijack --resume --data-block-sync \\
    --skip-prolog --skip-ip-block --skip-port-block --skip-baseline --skip-dns-audit \\
    --db $DB --out-dir $OUT \\
    "\${TF[@]}" || true
  NOW=\$(date +%s)
  if [ "\$NOW" -ge "\$END" ]; then
    break
  fi
  sleep 20
done
EOF
else
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
export BLOCKCHECKS_LUA_EXTRA="${BLOCKCHECKS_LUA_EXTRA-}"
export PYTHONUNBUFFERED=1
exec bs full \\
  --max-timeh $HOURS \\
  --domains-file $DOMAINS \\
  --db $DB \\
  --out-dir $OUT \\
  --parallel 4 \\
  $EXTRA \\
  --allow-dns-hijack \\
  --resume \\
  --data-block-sync \\
  --skip-prolog \\
  --skip-ip-block \\
  --skip-port-block \\
  --isp-interface eth3
EOF
fi
chmod 700 "$RUNNER"

tmux new-session -d -s "$SESSION" -c "$ROOT" bash -lc "
set -o pipefail
source .venv/bin/activate
export BLOCKCHECKS_PROXY='${BLOCKCHECKS_PROXY-}'
export BLOCKCHECKS_LUA_EXTRA='${BLOCKCHECKS_LUA_EXTRA-}'
LOG='$LOG'
echo \"=== START \$(date -Is) variant=$VAR hours=$HOURS kind=$KIND ulimit=\$(ulimit -n) proxy=\${BLOCKCHECKS_PROXY:-none} lua_extra=\${BLOCKCHECKS_LUA_EXTRA:-none} ===\" | tee -a \"\$LOG\"
sudo -E env BLOCKCHECKS_PROXY='${BLOCKCHECKS_PROXY-}' BLOCKCHECKS_LUA_EXTRA='${BLOCKCHECKS_LUA_EXTRA-}' \"$RUNNER\" 2>&1 | tee -a \"\$LOG\"
ec=\${PIPESTATUS[0]}
rm -f \"$RUNNER\"
echo \"=== END \$(date -Is) exit=\$ec ===\" | tee -a \"\$LOG\"
exit \$ec
"

echo "started tmux:$SESSION variant=$VAR hours=$HOURS kind=$KIND log=$LOG"
echo "attach: tmux attach -t $SESSION"
if [ -n "$DOMAINS" ] && [ -f "$DOMAINS" ]; then
  echo "domains: $DOMAINS ($(grep -c . "$DOMAINS" 2>/dev/null || echo 0) lines)"
else
  echo "target: Discord-voice UDP 35.217.48.152:50004 (pair loop)"
fi
