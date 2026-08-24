#!/usr/bin/env bash
# cleanup_env.sh — reset all blockcheckS runtime state on the host:
#   * kill leftover nfqws2 (host + netns)
#   * kill leftover sudo bs full/scan/pair
#   * delete netns / veth pairs / iptables leftovers
#   * remove /dev/shm bridge IPC
#   * remove XDG run.lock (not cwd)
#
# Safe to run between test campaigns. Needs sudo.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STATE="${XDG_STATE_HOME:-$HOME/.local/state}/blockcheckS"

echo "=== cleanup blockcheckS runtime state ==="

sudo pkill -9 nfqws2 2>/dev/null || true
sudo pkill -9 -f 'bs (full|scan|pair)' 2>/dev/null || true

for ns in $(sudo ip netns list 2>/dev/null | awk '{print $1}'); do
  echo "  netns del $ns"
  sudo ip netns del "$ns" 2>/dev/null || true
done
# Only blockcheckS veth prefixes (vh-/vn-). NEVER match bare ^veth — that is
# Docker's naming scheme and deleting those tears the network off live
# containers (bitmagnet etc.).
for vh in $(ip -br link show 2>/dev/null | awk '{print $1}' | grep -E '^(vh-|vn-)'); do
  echo "  link del $vh"
  sudo ip link del "${vh%%@*}" 2>/dev/null || true
done
# Drop only blockcheckS FORWARD rules; never -F FORWARD — Docker keeps its
# published-port/isolation rules there and a flush breaks live containers.
while read -r rule; do
  [ -z "$rule" ] && continue
  # shellcheck disable=SC2086
  sudo iptables -D FORWARD $rule 2>/dev/null || true
done < <(sudo iptables -S FORWARD 2>/dev/null | grep -E '\-i vh\-|\-o vh\-|\-i vn\-|\-o vn\-' | sed 's/^-A FORWARD //')

# Sweep orphan NAT rules from SIGKILLed runs (pool teardown never ran).
while read -r rule; do
  [ -z "$rule" ] && continue
  # shellcheck disable=SC2086
  sudo iptables -t nat -D POSTROUTING $rule 2>/dev/null || true
done < <(sudo iptables -t nat -S POSTROUTING 2>/dev/null | grep '10\.200\.' | sed 's/^-A POSTROUTING //')

echo "  shm blockchecks: $(sudo rm -rf /dev/shm/blockchecks 2>/dev/null; echo removed)"
sudo rm -f "$STATE/run.lock" "$ROOT/run.lock"
echo "=== done — host is clean ==="
