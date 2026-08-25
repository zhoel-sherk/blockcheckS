#!/usr/bin/env bash
# Week coverage campaign: Discord → YouTube → residual lists → UDP voice.
# One tmux session (bs-week), one netns pool. Does NOT launch A→F.
#
# Usage:
#   scripts/run_week_coverage.sh              # S1→S5 from scratch
#   scripts/run_week_coverage.sh S3           # start at coverage-tcp
#   scripts/run_week_coverage.sh export       # bc-nfconf + provider PASS dump (no run)
#
# Monitor: tmux attach -t bs-week
#          scripts/monitor_series.sh week
# Stop current bs: bs stop
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source .venv/bin/activate

SESSION="${WEEK_SESSION:-bs-week}"
DB="${WEEK_DB:-logs/week_cov.db}"
UDP_DB="${WEEK_UDP_DB:-logs/week_cov_udp.db}"
OUT="${WEEK_OUT:-logs/week_cov_export}"
S1_H="${WEEK_S1_H:-48}"
S2_H="${WEEK_S2_H:-48}"
S3_H="${WEEK_S3_H:-24}"
S4A_H="${WEEK_S4A_H:-8}"
S4B_H="${WEEK_S4B_H:-8}"
S4C_H="${WEEK_S4C_H:-8}"
S5_H="${WEEK_S5_H:-24}"

export BLOCKCHECKS_BLOBS="${BLOCKCHECKS_BLOBS:-$ROOT/blobs}"
if [ -z "${BLOCKCHECKS_SETTINGS:-}" ] && [ -f "$ROOT/../dpi-tester/settings.ini" ]; then
  export BLOCKCHECKS_SETTINGS="$ROOT/../dpi-tester/settings.ini"
fi
export BLOCKCHECKS_PROXY="${BLOCKCHECKS_PROXY-}"
export BLOCKCHECKS_LUA_EXTRA="${BLOCKCHECKS_LUA_EXTRA-}"
export PYTHONUNBUFFERED=1
export PATH="$ROOT/.venv/bin:$PATH"
export HOME="${HOME:-/home/zhoel}"

dump_provider_pass() {
  "$ROOT/.venv/bin/python3" - "$DB" <<'PY'
import sqlite3, sys
from pathlib import Path
from blockchecks.data_block.provider import get_provider_dir

watch = (
    "updates.discord.com",
    "gateway.discord.gg",
    "discord.com",
    "youtube.com",
    "googlevideo.com",
)
run_db = Path(sys.argv[1])
prov = get_provider_dir() / "strategies.db"
print(f"provider={prov}")
if prov.is_file():
    con = sqlite3.connect(prov)
    rows = con.execute(
        "SELECT domain, COUNT(*) FROM pass_strategies "
        "WHERE domain IN ({}) GROUP BY domain ORDER BY domain".format(
            ",".join("?" * len(watch))
        ),
        watch,
    ).fetchall()
    total = con.execute("SELECT COUNT(*) FROM pass_strategies").fetchone()[0]
    print(f"  pass_strategies total={total}")
    for d, n in rows:
        print(f"  {d}: {n}")
    missing = [d for d in watch if d not in {r[0] for r in rows}]
    if missing:
        print(f"  missing PASS: {', '.join(missing)}")
else:
    print("  (no provider strategies.db)")
if run_db.is_file():
    con = sqlite3.connect(run_db)
    try:
        n = con.execute("SELECT COUNT(*) FROM tcp_results").fetchone()[0]
        st = dict(con.execute("SELECT status, COUNT(*) FROM tcp_results GROUP BY status"))
        print(f"week_db={run_db} results={n} statuses={st}")
        for d in watch:
            p = con.execute(
                "SELECT COUNT(*) FROM tcp_results WHERE domain=? AND status='PASS'",
                (d,),
            ).fetchone()[0]
            t = con.execute(
                "SELECT COUNT(*) FROM tcp_results WHERE domain=?", (d,)
            ).fetchone()[0]
            print(f"  run {d}: pass={p} / {t}")
    except sqlite3.Error as exc:
        print(f"  week_db: {exc}")
PY
}

do_export() {
  mkdir -p "$OUT"
  echo "===== EXPORT $(date -Is) db=$DB ====="
  if [ ! -f "$DB" ]; then
    echo "no $DB yet — skip bc-nfconf" >&2
    dump_provider_pass
    return 0
  fi
  bc-nfconf --db "$DB" --out-dir "$OUT" --isp-interface eth3 \
    --domains-file presets/domains/coverage-tcp.txt || true
  dump_provider_pass
}

if [ "${1:-}" = "export" ]; then
  do_export
  exit 0
fi

FIRST="${1:-S1}"
case "$FIRST" in
  S4) FIRST="S4a" ;;
  S1|S2|S3|S4a|S4b|S4c|S5) ;;
  *)
    echo "usage: $0 [S1|S2|S3|S4|S4a|S4b|S4c|S5|export]" >&2
    exit 2
    ;;
esac

cleanup_leftovers() {
  # Names are bs-p-<pid%10000>-<i> + hashed vh-/vn- (not the old bs-p-0).
  sudo pkill -9 nfqws2 2>/dev/null || true
  for ns in $(ip netns list 2>/dev/null | awk '{print $1}' | grep -E '^bs-p-' || true); do
    sudo ip netns del "$ns" 2>/dev/null || true
  done
  for vh in $(ip -br link show 2>/dev/null | awk '{print $1}' | grep -E '^(vh-|vn-)' || true); do
    sudo ip link del "${vh%@*}" 2>/dev/null || true
  done
}

run_tcp_stage() {
  local id="$1" preset="$2" hours="$3"
  local runner
  runner="$(mktemp /tmp/bs_week_${id}.XXXXXX.sh)"
  cat >"$runner" <<EOF
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
  --preset $preset \\
  --tcp-only \\
  --max-timeh $hours \\
  --db $DB \\
  --out-dir $OUT \\
  --parallel 4 \\
  --bridge-batch 10 \\
  --timeout 2 \\
  --scan-level full \\
  --adaptive-epsilon 0.1 \\
  --no-preflight --no-wssize --no-settle-profile \\
  --allow-dns-hijack --skip-dns-audit \\
  --resume --data-block-sync \\
  --skip-prolog --skip-ip-block --skip-port-block \\
  --isp-interface eth3
EOF
  chmod 700 "$runner"
  echo "===== STAGE $id preset=$preset ${hours}h $(date -Is) ====="
  set +e
  sudo -E env HOME="$HOME" BLOCKCHECKS_PROXY="${BLOCKCHECKS_PROXY-}" \
    BLOCKCHECKS_LUA_EXTRA="${BLOCKCHECKS_LUA_EXTRA-}" \
    BLOCKCHECKS_NFQWS2_DEBUG="${BLOCKCHECKS_NFQWS2_DEBUG-}" "$runner"
  local rc=$?
  set -e
  rm -f "$runner"
  echo "===== STAGE $id exit=$rc $(date -Is) ====="
  if [ "$rc" -eq 2 ]; then
    echo "stage $id CLI/config error — aborting week" >&2
    exit 2
  fi
  if [ "$rc" -eq 4 ]; then
    echo "fingerprint mismatch on $id — not retrying, next stage"
  elif [ "$rc" -ne 0 ]; then
    echo "stage $id failed rc=$rc — continuing"
  fi
}

run_udp_stage() {
  local hours="$1"
  local runner
  runner="$(mktemp /tmp/bs_week_S5.XXXXXX.sh)"
  cat >"$runner" <<EOF
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
export PYTHONUNBUFFERED=1
END=\$(( \$(date +%s) + ${hours} * 3600 ))
echo "=== S5 UDP loop until \$(date -d @\$END -Is 2>/dev/null || date -Is) ==="
while true; do
  NOW=\$(date +%s)
  REMAIN=\$(( END - NOW ))
  if [ "\$REMAIN" -lt 90 ]; then
    echo "=== S5 time budget exhausted remain=\$REMAIN ==="
    break
  fi
  if [ "\$REMAIN" -ge 3600 ]; then
    TF=(--max-timeh "\$(python3 -c "print(\$REMAIN/3600.0)")")
  else
    TF=(--max-timem "\$(python3 -c "print(\$REMAIN/60.0)")")
  fi
  echo "=== S5 wave remain=\${REMAIN}s \${TF[*]} \$(date -Is) ==="
  set +e
  bs pair -d discord.com --generate \\
    --tcp-sources fake \\
    --udp-sources custom,standard_udp,configs,flowseal \\
    --scan-level full --max 200 --udp-bypass \\
    --ip 35.217.48.152 --port 50004 --discover-dns 5 \\
    --parallel 2 --timeout 3 --udp-timeout 3 \\
    --allow-dns-hijack --resume --data-block-sync --no-preflight \\
    --skip-prolog --skip-ip-block --skip-port-block --skip-baseline --skip-dns-audit \\
    --db $UDP_DB --out-dir $OUT \\
    "\${TF[@]}"
  rc=\$?
  set -e
  if [ "\$rc" -eq 4 ]; then
    echo "=== S5 stop: matrix fingerprint mismatch (not retrying) ==="
    break
  fi
  NOW=\$(date +%s)
  if [ "\$NOW" -ge "\$END" ]; then
    break
  fi
  sleep 20
done
EOF
  chmod 700 "$runner"
  echo "===== STAGE S5 Discord UDP ${hours}h $(date -Is) ====="
  set +e
  sudo -E env HOME="$HOME" BLOCKCHECKS_PROXY="${BLOCKCHECKS_PROXY-}" "$runner"
  local rc=$?
  set -e
  rm -f "$runner"
  echo "===== STAGE S5 exit=$rc $(date -Is) ====="
}

should_run() {
  local id="$1" started=0 s
  for s in S1 S2 S3 S4a S4b S4c S5; do
    [ "$s" = "$FIRST" ] && started=1
    if [ "$started" = 1 ] && [ "$s" = "$id" ]; then
      return 0
    fi
  done
  return 1
}

run_inner() {
  cleanup_leftovers
  if should_run S1; then run_tcp_stage S1 discord "$S1_H"; cleanup_leftovers; fi
  if should_run S2; then run_tcp_stage S2 google-youtube "$S2_H"; cleanup_leftovers; fi
  if should_run S3; then run_tcp_stage S3 coverage-tcp "$S3_H"; cleanup_leftovers; fi
  if should_run S4a; then run_tcp_stage S4a amazon-aws "$S4A_H"; cleanup_leftovers; fi
  if should_run S4b; then run_tcp_stage S4b cloudflare "$S4B_H"; cleanup_leftovers; fi
  if should_run S4c; then run_tcp_stage S4c diagnostic "$S4C_H"; cleanup_leftovers; fi
  echo "===== TCP stages done — snapshot export ====="
  do_export
  if should_run S5; then run_udp_stage "$S5_H"; cleanup_leftovers; fi
  echo "===== WEEK COMPLETE $(date -Is) ====="
  do_export
}

if [ "${WEEK_INNER:-}" = 1 ]; then
  run_inner
  exit 0
fi

busy_sessions=""
for s in bs-series bs-week bs-run-A bs-run-B bs-run-C bs-run-D bs-run-E bs-run-F bs-run-G; do
  if tmux has-session -t "$s" 2>/dev/null; then
    busy_sessions="$busy_sessions $s"
  fi
done
if [ -n "$busy_sessions" ]; then
  echo "refuse: tmux already running:$busy_sessions" >&2
  echo "week coverage is sequential-only (one netns pool). Stop A→F first." >&2
  exit 1
fi

LOCK="${XDG_STATE_HOME:-$HOME/.local/state}/blockcheckS/run.lock"
if [ -f "$LOCK" ]; then
  lock_pid="$("$ROOT/.venv/bin/python3" -c "import json,sys; print(json.load(open(sys.argv[1])).get('pid') or '')" "$LOCK" 2>/dev/null || true)"
  if [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null; then
    echo "refuse: active run.lock pid=$lock_pid ($LOCK)" >&2
    exit 1
  fi
fi

mkdir -p logs "$OUT"
TS="$(date +%Y%m%d_%H%M%S)"
LOG="logs/week_cov_${TS}.log"
echo "$LOG" > logs/week_cov_LATEST.logpath

tmux new-session -d -s "$SESSION" -c "$ROOT" bash -lc "
set -o pipefail
source .venv/bin/activate
LOG='$LOG'
echo \"=== WEEK START \$(date -Is) first=$FIRST db=$DB udp=$UDP_DB ===\" | tee -a \"\$LOG\"
WEEK_INNER=1 WEEK_SESSION='$SESSION' WEEK_DB='$DB' WEEK_UDP_DB='$UDP_DB' \\
  WEEK_OUT='$OUT' WEEK_S1_H='$S1_H' WEEK_S2_H='$S2_H' WEEK_S3_H='$S3_H' \\
  WEEK_S4A_H='$S4A_H' WEEK_S4B_H='$S4B_H' WEEK_S4C_H='$S4C_H' WEEK_S5_H='$S5_H' \\
  '$ROOT/scripts/run_week_coverage.sh' '$FIRST' 2>&1 | tee -a \"\$LOG\"
ec=\${PIPESTATUS[0]}
echo \"=== WEEK END \$(date -Is) exit=\$ec ===\" | tee -a \"\$LOG\"
exit \$ec
"

echo "week coverage started: tmux:$SESSION first=$FIRST"
echo "db: $DB  udp: $UDP_DB  out: $OUT"
echo "attach: tmux attach -t $SESSION"
echo "monitor: scripts/monitor_series.sh week"
echo "log: $LOG"
echo "export snapshot: scripts/run_week_coverage.sh export"
echo "stop: bs stop   (does not kill the orchestrator; next stage still starts)"
