#!/usr/bin/env bash
# cleanup_env.sh — reset all blockcheckS runtime state on the host:
#   * kill leftover nfqws2 (host + netns)
#   * delete netns / veth pairs / iptables leftovers
#   * remove /dev/shm bridge IPC
#   * remove stale run.lock
#
# Safe to run between test campaigns. Needs sudo.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== cleanup blockcheckS runtime state ==="

sudo pkill -9 nfqws2 2>/dev/null || true
pkill -9 -f 'bs (full|scan|pair) ' 2>/dev/null || true

for ns in $(sudo ip netns list 2>/dev/null | awk '{print $1}'); do
  echo "  netns del $ns"
  sudo ip netns del "$ns" 2>/dev/null || true
done
for vh in $(ip -br link show 2>/dev/null | awk '{print $1}' | grep '^vh-bs-p'); do
  echo "  link del $vh"
  sudo ip link del "$vh" 2>/dev/null || true
done
sudo iptables -F FORWARD 2>/dev/null || true

echo "  shm blockchecks: $(sudo rm -rf /dev/shm/blockchecks 2>/dev/null; echo removed)"
rm -f run.lock
echo "=== done — host is clean ==="
