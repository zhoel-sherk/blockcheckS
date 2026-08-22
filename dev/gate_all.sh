#!/usr/bin/env bash
# gate_all.sh — run every static/unit quality gate in one shot.
#
#   bash dev/gate_all.sh               → unit + quality + ruff + vulture
#   bash dev/gate_all.sh --integration → also runs the sudo integration suite
#
# Exits non-zero on the first failing gate.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="${ROOT}/.venv/bin/python"
RUFF="${ROOT}/.venv/bin/ruff"

echo "=== gate: pytest unit ==="
"$PY" -m pytest tests/ -q -p no:cacheprovider

echo "=== gate: pytest quality ==="
"$PY" -m pytest -m quality -q -p no:cacheprovider

echo "=== gate: ruff ==="
"$RUFF" check src tests

echo "=== gate: vulture ==="
if [ -x "${ROOT}/.venv/bin/vulture" ]; then
  "${ROOT}/.venv/bin/vulture" --config pyproject.toml
else
  echo "vulture not installed — skip"
fi

if [ "${1:-}" = "--integration" ]; then
  echo "=== gate: integration (sudo, ~10-15 min) ==="
  # E2E netns tests run long — raise pytest-timeout for the integration suite.
  sudo -n "$PY" -m pytest tests/integration/ -m integration -q --timeout=600
fi

echo "ALL GATES PASSED"
