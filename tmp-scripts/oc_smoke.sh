#!/bin/bash
set -euo pipefail
cd /home/zhoel/workspace/blockcheckS
export PATH="/home/zhoel/.opencode/bin:$PATH"
opencode run \
  --dir /home/zhoel/workspace/blockcheckS \
  -m opencode-go/deepseek-v4-flash \
  --title cursor-ssh-smoke \
  --auto \
  "Read-only smoke. Do NOT modify any files. Run git rev-parse --short HEAD. Then run .venv/bin/python -m pytest -m 'not integration' -q --tb=no. Reply with HEAD and pytest counts only."
