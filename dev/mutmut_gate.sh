#!/usr/bin/env bash
# Run scoped mutation testing — paths/filters from pyproject [tool.mutmut] only.
set -euo pipefail
cd "$(dirname "$0")/.."
exec mutmut run "$@"
