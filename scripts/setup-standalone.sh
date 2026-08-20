#!/usr/bin/env bash
# Install blockcheckS on Raspberry Pi (armv7l) or any Linux host without compiling.
# Required deps ship wheels on PyPI (including armv7l). rss sampling uses /proc, not psutil.
#
# Usage:
#   bash scripts/setup-standalone.sh              # venv + pip install + deps check
#   bash scripts/setup-standalone.sh --no-venv    # current environment
#   bash scripts/setup-standalone.sh --system     # system pip
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ARCH="$(uname -m)"
echo "=== blockcheckS standalone setup (arch: $ARCH) ==="

if [[ "$ARCH" == "armv7l" || "$ARCH" == "armv6l" ]]; then
  echo "  [arch] Raspberry Pi (32-bit) — wheels available, no compilation expected"
fi

# ── venv ──────────────────────────────────────────────────────────────
VENV="$ROOT/.venv"
USE_VENV=1
if [[ "${1:-}" == "--no-venv" ]]; then
  USE_VENV=0
elif [[ "${1:-}" == "--system" ]]; then
  USE_VENV=0
fi

if [[ "$USE_VENV" == "1" ]]; then
  if [[ ! -x "$VENV/bin/python" ]]; then
    echo "  [venv] creating $VENV"
    python3 -m venv "$VENV"
  fi
  PIP="$VENV/bin/pip"
  PY="$VENV/bin/python"
else
  PIP="$(command -v pip3 || command -v pip)"
  PY="$(command -v python3)"
fi

echo "  [pip] $PIP"
echo "  [python] $PY"

# ── install ───────────────────────────────────────────────────────────
echo "  [install] pip install -e ."
"$PIP" install --upgrade pip
"$PIP" install -e "$ROOT"

# ── smoke: import + metrics (no psutil) ───────────────────────────────
echo "  [smoke] import blockchecks + metrics without psutil"
"$PY" - <<'PYEOF'
import os
import blockchecks  # noqa: F401
from blockchecks.service.metrics import process_rss_bytes
rss = process_rss_bytes(os.getpid())
assert rss > 0, "process_rss_bytes returned 0 — /proc not readable?"
print(f"  ok: import blockchecks, self RSS={rss} bytes")
PYEOF

# ── nfqws2 dependency (system_deps fetch on first use) ────────────────
echo "  [deps] nfqws2 will be resolved by bs at first run (or run: bs tcp --skip-deps-check -d discord.com -s 'fake:blob=stun')"
echo "  [netns] ensure: sudo ip netns / iptables available (nfqws2 tests need root)"

cat <<'EOF'

=== Done ===

Probe a strategy (needs root + nfqws2):
  sudo -E .venv/bin/bs tcp -d discord.com -s "fake:blob=stun:repeats=6:tcp_ts=-1000" --skip-deps-check

RPi2: curl-cffi and pydantic-core wheels are on PyPI for armv7l; no compile.
nfqws2 for arm is fetched on first use (system_deps: armv7l → binaries/linux-arm).
EOF
