#!/bin/bash
set -euo pipefail
export PATH="/home/zhoel/.opencode/bin:/usr/bin:/bin"
export XDG_DATA_HOME=/tmp/oc-iso/data
export XDG_STATE_HOME=/tmp/oc-iso/state
export XDG_CONFIG_HOME=/tmp/oc-iso/config
mkdir -p "$XDG_DATA_HOME/opencode"
cp -a /home/zhoel/.local/share/opencode/auth.json "$XDG_DATA_HOME/opencode/" 2>/dev/null || true
cd /home/zhoel/workspace/blockcheckS
opencode run \
  --dir /home/zhoel/workspace/blockcheckS \
  -m opencode-go/deepseek-v4-flash \
  --title iso-smoke \
  --auto \
  --print-logs \
  --log-level INFO \
  "Say only the word pong. Do not use any tools."
