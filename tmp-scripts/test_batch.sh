#!/bin/bash
# test_batch.sh — blockcheckS validation batch against GP results
# Usage: sudo bash tmp-scripts/test_batch.sh [yt|discord|all]
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BS="$PROJECT_DIR/bs.py"
PYTHON="/home/zhoel/workspace/dpi-tester/.venv/bin/python"
DB="$PROJECT_DIR/state.db"

GREEN='\033[1;32m'
RED='\033[1;31m'
CYAN='\033[1;36m'
RESET='\033[0m'

log_header() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${RESET}"
    echo -e "${CYAN}  $1${RESET}"
    echo -e "${CYAN}════════════════════════════════════════════════${RESET}"
}

run_scan() {
    local domain="$1"
    local source="$2"
    local max="${3:-15}"
    log_header "Scan: $domain ($source, max=$max)"
    sudo "$PYTHON" "$BS" scan \
        -d "$domain" \
        --user-matrix "/tmp_scripts/gp_verified.txt" \
        --generate "$source" \
        --max "$max" \
        --parallel 4 \
        --timeout 5 \
        --db "$DB" \
        --tcp-sources "fake_multi,hostfake,fake_faked,custom"
}

show_results() {
    log_header "Results Summary"
    "$PYTHON" -c "
import aiosqlite, asyncio
async def show():
    async with aiosqlite.connect('$DB') as db:
        print('=== Working TCP strategies ===')
        r = await db.execute('SELECT strategy, domain, http_code, latency_ms FROM v_working_tcp ORDER BY domain, latency_ms')
        count = 0
        rows = await r.fetchall()
        for name, dom, code, lat in rows:
            print(f'  {dom:25s} {name[:40]:40s} HTTP {code} {lat:.0f}ms')
            count += 1
        print(f'  Total: {count} working pairs')
        
        print()
        print('=== Domain coverage ===')
        r = await db.execute('SELECT * FROM v_coverage')
        for name, proto, count, avg_lat in await r.fetchall():
            print(f'  {name[:40]:40s} {proto:5s} {count} domains avg={avg_lat:.0f}ms')
        
        print()
        print('=== Latest run ===')
        r = await db.execute('SELECT * FROM v_latest_run')
        for dom, total, passed, avg, ts in await r.fetchall():
            tag = '\033[32m' if passed > 0 else '\033[31m'
            print(f'  {tag}{dom:25s} {passed}/{total} PASS avg={avg:.0f}ms \033[0m {ts}')
asyncio.run(show())
" 2>/dev/null
}

# Cleanup
cleanup() {
    sudo pkill -9 nfqws2 2>/dev/null || true
    sudo iptables -F OUTPUT 2>/dev/null || true
    for i in 0 1 2 3 4; do
        sudo ip netns delete "bs-p-$i" 2>/dev/null || true
        sudo ip link delete "vh-bs-p-$i" 2>/dev/null || true
    done
}
trap cleanup EXIT
cleanup

case "${1:-all}" in
    yt)
        for d in $(cat /tmp_scripts/domains_yt.txt); do
            run_scan "$d" "fake_multi,hostfake,custom" 10
        done
        ;;
    discord)
        for d in $(cat /tmp_scripts/domains_discord.txt); do
            run_scan "$d" "fake_multi,hostfake,custom" 10
        done
        ;;
    all)
        for d in $(cat /tmp_scripts/domains_yt.txt /tmp_scripts/domains_discord.txt); do
            run_scan "$d" "fake_multi,hostfake,custom" 10
        done
        ;;
esac

show_results
