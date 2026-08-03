"""Dead-code gate — policy in [tool.vulture], no CLI thresholds in this file."""

from __future__ import annotations

import shutil
import subprocess

import pytest
from tests.unit._quality_config import PROJECT_ROOT

pytestmark = [pytest.mark.unit, pytest.mark.quality]


def test_vulture_no_dead_code() -> None:
    vulture = shutil.which("vulture") or str(PROJECT_ROOT / ".venv" / "bin" / "vulture")
    if not shutil.which("vulture") and not (PROJECT_ROOT / ".venv" / "bin" / "vulture").is_file():
        pytest.skip("vulture not installed (pip install -e '.[dev]')")

    # Paths / min_confidence / ignore_* come from [tool.vulture] in pyproject.toml.
    proc = subprocess.run(
        [vulture, "--config", str(PROJECT_ROOT / "pyproject.toml")],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        return
    out = (proc.stdout or "") + (proc.stderr or "")
    pytest.fail(f"vulture found dead code ({proc.returncode}):\n{out}")
