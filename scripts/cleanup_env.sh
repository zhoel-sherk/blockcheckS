#!/usr/bin/env bash
# cleanup_env.sh — reset leftover blockcheckS runtime state on the host.
#
# Modes:
#   (default) full reset BETWEEN campaigns: pkill leftover nfqws2 + bs,
#             delete all netns, vh-/vn- veths, NAT leftovers, shm, run.lock.
#   --orphans-only  do NOT pkill the pid in run.lock; only delete netns whose
#                   names are NOT live campaign workers. Always rmdir
#                   /etc/netns/<ns> after ip netns del (pool already does this
#                   on clean teardown; this script historically did not).
#
# NEVER match bare ^veth — that is Docker's naming (bitmagnet etc.).
# Host-wide `pkill -9 nfqws2` is full-reset only.
#
# Usage:
#   sudo bash scripts/cleanup_env.sh
#   sudo bash scripts/cleanup_env.sh --orphans-only [--exclude-prefix=bs-p-7403]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STATE="${XDG_STATE_HOME:-$HOME/.local/state}/blockcheckS"
ORPHANS_ONLY=0
EXCLUDE_PREFIX=""

for arg in "$@"; do
  case "$arg" in
    --orphans-only) ORPHANS_ONLY=1 ;;
    --exclude-prefix=*) EXCLUDE_PREFIX="${arg#--exclude-prefix=}" ;;
    -h|--help)
      sed -n '2,18p' "$0"
      exit 0
      ;;
    *)
      echo "unknown arg: $arg" >&2
      exit 2
      ;;
  esac
done

lock_pid=""
if [ -f "$STATE/run.lock" ]; then
  lock_pid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("pid") or "")' "$STATE/run.lock" 2>/dev/null || true)"
fi

if [ "$ORPHANS_ONLY" -eq 1 ] && [ -z "$EXCLUDE_PREFIX" ]; then
  if [ -n "$lock_pid" ]; then
    # NetNsPool base is bs-p-{pid%10000:04d}
    EXCLUDE_PREFIX="$(python3 -c 'import sys; print(f"bs-p-{int(sys.argv[1]) % 10000:04d}-")' "$lock_pid")"
    echo "  orphans-only: auto exclude-prefix=$EXCLUDE_PREFIX (from run.lock pid=$lock_pid)"
  else
    echo "ERROR: --orphans-only requires --exclude-prefix=bs-p-<pid%10000>- or a live run.lock" >&2
    exit 2
  fi
fi

is_protected() {
  local ns="$1"
  [ -n "$EXCLUDE_PREFIX" ] && [[ "$ns" == "$EXCLUDE_PREFIX"* ]] && return 0
  return 1
}

echo "=== cleanup blockcheckS runtime state (orphans_only=$ORPHANS_ONLY prefix=${EXCLUDE_PREFIX:-none}) ==="

if [ "$ORPHANS_ONLY" -eq 0 ]; then
  # Full reset — between campaigns only. Do not run while week_cov holds run.lock.
  echo "  pkill nfqws2 (host-wide, between-campaigns only)"
  sudo pkill -9 nfqws2 2>/dev/null || true
  sudo pkill -9 -f 'bs (full|scan|pair)' 2>/dev/null || true
else
  echo "  orphans-only: skip pkill of run.lock pid=${lock_pid:-none}"
fi

for ns in $(sudo ip netns list 2>/dev/null | awk '{print $1}'); do
  if [ "$ORPHANS_ONLY" -eq 1 ] && is_protected "$ns"; then
    echo "  keep live $ns"
    continue
  fi
  echo "  netns del $ns"
  sudo ip netns del "$ns" 2>/dev/null || true
  sudo rm -rf "/etc/netns/$ns"
done

# Stale /etc/netns dirs left when ip netns del ran without rmdir (old script / crash).
if [ -d /etc/netns ]; then
  for d in /etc/netns/*; do
    [ -e "$d" ] || continue
    name="$(basename "$d")"
    if [ "$ORPHANS_ONLY" -eq 1 ] && is_protected "$name"; then
      continue
    fi
    if sudo ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$name"; then
      continue
    fi
    echo "  rmdir stale /etc/netns/$name"
    sudo rm -rf "$d"
  done
fi

# Only blockcheckS veth prefixes (vh-/vn-). NEVER match bare ^veth — Docker.
for vh in $(ip -br link show 2>/dev/null | awk '{print $1}' | grep -E '^(vh-|vn-)' || true); do
  peer="${vh%%@*}"
  if [ "$ORPHANS_ONLY" -eq 1 ]; then
    # Keep veths still attached to a protected netns (best-effort: skip if UP and a protected ns exists).
    skip=0
    if [ -n "$EXCLUDE_PREFIX" ]; then
      for ns in $(sudo ip netns list 2>/dev/null | awk '{print $1}'); do
        is_protected "$ns" || continue
        if sudo ip netns exec "$ns" ip -br link show 2>/dev/null | grep -q "$peer"; then
          skip=1
          break
        fi
      done
    fi
    [ "$skip" -eq 1 ] && echo "  keep veth $peer" && continue
  fi
  echo "  link del $peer"
  sudo ip link del "$peer" 2>/dev/null || true
done

# Drop only blockcheckS FORWARD rules; never -F FORWARD.
while read -r rule; do
  [ -z "$rule" ] && continue
  # shellcheck disable=SC2086
  sudo iptables -D FORWARD $rule 2>/dev/null || true
done < <(sudo iptables -S FORWARD 2>/dev/null | grep -E '\-i vh\-|\-o vh\-|\-i vn\-|\-o vn\-' | sed 's/^-A FORWARD //' || true)

if [ "$ORPHANS_ONLY" -eq 0 ]; then
  while read -r rule; do
    [ -z "$rule" ] && continue
    # shellcheck disable=SC2086
    sudo iptables -t nat -D POSTROUTING $rule 2>/dev/null || true
  done < <(sudo iptables -t nat -S POSTROUTING 2>/dev/null | grep '10\.200\.' | sed 's/^-A POSTROUTING //' || true)
  echo "  shm blockchecks: $(sudo rm -rf /dev/shm/blockchecks 2>/dev/null; echo removed)"
  sudo rm -f "$STATE/run.lock" "$ROOT/run.lock"
else
  echo "  orphans-only: leave NAT/shm/run.lock for live campaign"
fi

echo "=== done ==="
