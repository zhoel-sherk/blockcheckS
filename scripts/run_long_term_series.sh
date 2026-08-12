#!/usr/bin/env bash
# Sequential long-term run orchestrator: A → B → C → D → E → F.
# Each variant runs up to HOURS (default 20h) via run_variant.sh; the next
# starts only after the previous tmux session finishes (END marker).
#
# The orchestrator itself runs inside a detached tmux session (bs-series) so
# it survives terminal close. Monitor with: tmux attach -t bs-series
#
# Usage: scripts/run_long_term_series.sh [hours] [first-variant]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HOURS="${1:-20}"
FIRST="${2:-A}"
VARIANTS="A B C D E F"
# trim before FIRST
STARTED=0
LIST=""
for v in $VARIANTS; do
  if [ "$v" = "$FIRST" ]; then STARTED=1; fi
  if [ "$STARTED" = 1 ]; then LIST="$LIST $v"; fi
done
[ -n "$LIST" ] || LIST="A"

SERIES_SESSION="bs-series"

# If already running, refuse.
if tmux has-session -t "$SERIES_SESSION" 2>/dev/null; then
  echo "series session '$SERIES_SESSION' already running" >&2
  echo "attach: tmux attach -t $SERIES_SESSION" >&2
  exit 1
fi

mkdir -p logs
SERIES_LOG="logs/long_term_series_$(date +%Y%m%d_%H%M%S).log"
echo "series log: $SERIES_LOG"

tmux new-session -d -s "$SERIES_SESSION" -c "$ROOT" bash -lc "
set -o pipefail
for VAR in $LIST; do
  echo \"===== SERIES: launching variant \$VAR (\$(date -Is)) =====\" | tee -a '$SERIES_LOG'
  scripts/run_variant.sh \$VAR $HOURS 2>&1 | tee -a '$SERIES_LOG'
  # wait for the variant's tmux session to finish
  while tmux has-session -t \"bs-run-\$VAR\" 2>/dev/null; do
    sleep 60
  done
  echo \"===== SERIES: variant \$VAR done (\$(date -Is)) =====\" | tee -a '$SERIES_LOG'
done
echo \"===== SERIES: ALL VARIANTS COMPLETE (\$(date -Is)) =====\" | tee -a '$SERIES_LOG'
"

echo "series started: tmux:$SERIES_SESSION variants:[$LIST] hours=$HOURS"
echo "monitor: tmux attach -t $SERIES_SESSION"
echo "log: $SERIES_LOG"
