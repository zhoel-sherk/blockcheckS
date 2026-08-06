#!/usr/bin/env bash
# speed_benchmark.sh — compare blockcheck2.sh vs blockcheckS-classic vs blockcheckS-lua
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
RESULTS="logs/speed_bench_$(date +%Y%m%d_%H%M).jsonl"
DOMAIN="discord.com"
TIMEOUT=8
MAX=50
REPEATS=3
BS="$ROOT/.venv/bin/bs"

echo "=== blockcheckS speed benchmark ==="
echo "Domain: $DOMAIN | Max: $MAX | Timeout: ${TIMEOUT}s | Runs: $REPEATS"
echo "Results: $RESULTS"
echo "Start: $(date -Is)"
echo ""

cleanup() {
    sudo pkill -9 nfqws2 2>/dev/null || true
    sudo iptables -F OUTPUT 2>/dev/null || true
    for i in 0 1 2 3; do
        sudo ip netns del "bs-p-$i" 2>/dev/null || true
        sudo ip link del "vh-bs-p-$i" 2>/dev/null || true
    done
    sudo rm -rf /dev/shm/blockchecks 2>/dev/null || true
}
trap cleanup EXIT

for run in $(seq 1 $REPEATS); do
    echo "=== Run $run/$REPEATS ==="

    # ── blockcheck2.sh ──
    cleanup; sleep 2
    echo "  [1/3] blockcheck2.sh..."
    t0=$SECONDS
    sudo -E env ZAPRET_BASE=/opt/zapret2 \
        DOMAINS="$DOMAIN" \
        ENABLE_HTTP=0 ENABLE_HTTP3=0 ENABLE_CUSTOM=1 \
        TEST=custom \
        /opt/zapret2/blockcheck2.sh -y -t "$TIMEOUT" > /tmp/bc2_out.txt 2>&1 || true
    bc2_time=$(($SECONDS - t0))
    echo "  blockcheck2.sh: ${bc2_time}s"

    # ── blockcheckS classic ──
    cleanup; sleep 2
    echo "  [2/3] blockcheckS-classic..."
    t0=$SECONDS
    sudo "$BS" scan \
        --domain "$DOMAIN" \
        --generate standard \
        --max "$MAX" \
        --parallel 4 \
        --timeout "$TIMEOUT" \
        --scan-level fast \
        --skip-dns-audit --skip-prolog --skip-ip-block --skip-port-block --skip-baseline \
        --skip-deps-check --no-wssize \
        > /tmp/bs_classic_out.txt 2>&1 || true
    classic_time=$(($SECONDS - t0))
    classic_pass=$(grep -c 'OK\|THROTTLED' /tmp/bs_classic_out.txt 2>/dev/null || echo 0)
    echo "  classic: ${classic_time}s (${classic_pass} PASS)"

    # ── blockcheckS lua-bridge ──
    cleanup; sleep 2
    echo "  [3/3] blockcheckS-lua..."
    t0=$SECONDS
    sudo "$BS" scan \
        --domain "$DOMAIN" \
        --generate standard \
        --max "$MAX" \
        --parallel 4 \
        --timeout "$TIMEOUT" \
        --scan-level fast \
        --lua-bridge --bridge-batch "$MAX" \
        --skip-dns-audit --skip-prolog --skip-ip-block --skip-port-block --skip-baseline \
        --skip-deps-check --no-wssize \
        > /tmp/bs_lua_out.txt 2>&1 || true
    lua_time=$(($SECONDS - t0))
    lua_pass=$(grep -c 'OK\|THROTTLED' /tmp/bs_lua_out.txt 2>/dev/null || echo 0)
    echo "  lua-bridge: ${lua_time}s (${lua_pass} PASS)"

    echo "{\"run\":$run,\"blockcheck2_sh\":$bc2_time,\"classic_time\":$classic_time,\"classic_pass\":$classic_pass,\"lua_time\":$lua_time,\"lua_pass\":$lua_pass}" >> "$RESULTS"
    echo ""
done

# ── Summary ──
echo "=== Results ==="
echo ""
python3 -c "
import json
rows = []
with open('$RESULTS') as f:
    for line in f:
        rows.append(json.loads(line.strip()))
if not rows:
    print('No results')
    exit(1)
bc2_avg = sum(r['blockcheck2_sh'] for r in rows) / len(rows)
classic_avg = sum(r['classic_time'] for r in rows) / len(rows)
lua_avg = sum(r['lua_time'] for r in rows) / len(rows)
print(f'blockcheck2.sh:    {bc2_avg:.0f}s avg ({bc2_avg/$MAX:.1f}s/strategy)')
print(f'classic:           {classic_avg:.0f}s avg ({$MAX/classic_avg:.2f} tests/sec)')
print(f'lua-bridge:        {lua_avg:.0f}s avg ({$MAX/lua_avg:.2f} tests/sec)')
print(f'')
print(f'lua vs classic:    {classic_avg/lua_avg:.1f}x faster')
print(f'lua vs blockcheck2: {bc2_avg/lua_avg:.1f}x faster')
"

cleanup
echo ""
echo "=== Done ==="
