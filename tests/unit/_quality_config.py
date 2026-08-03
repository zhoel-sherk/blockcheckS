"""Load quality policy sections from pyproject.toml (single source of truth)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = PROJECT_ROOT / "pyproject.toml"


def load_pyproject() -> dict[str, Any]:
    with PYPROJECT.open("rb") as f:
        return tomllib.load(f)


def tool_section(*keys: str) -> dict[str, Any]:
    data: Any = load_pyproject()
    for key in keys:
        data = data.get(key, {})
        if not isinstance(data, dict):
            return {}
    return data
