"""Mutation gate config smoke + optional mutmut run (marker: mutation)."""

from __future__ import annotations

import shutil
import subprocess

import pytest
from tests.unit._quality_config import PROJECT_ROOT, tool_section

pytestmark = pytest.mark.unit


@pytest.mark.quality
def test_mutmut_config_present() -> None:
    cfg = tool_section("tool", "mutmut")
    paths = cfg.get("source_paths") or []
    assert paths, "[tool.mutmut].source_paths must be non-empty in pyproject.toml"
    assert cfg.get("pytest_add_cli_args_test_selection"), (
        "[tool.mutmut].pytest_add_cli_args_test_selection required"
    )


@pytest.mark.mutation
@pytest.mark.slow
def test_mutmut_no_survivors() -> None:
    """Run mutmut using [tool.mutmut] only — prefer CI workflow_dispatch for this."""
    mutmut = shutil.which("mutmut") or str(PROJECT_ROOT / ".venv" / "bin" / "mutmut")
    if not shutil.which("mutmut") and not (PROJECT_ROOT / ".venv" / "bin" / "mutmut").is_file():
        pytest.skip("mutmut not installed (pip install -e '.[dev]')")

    proc = subprocess.run(
        [mutmut, "run"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=3600,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        pytest.fail(f"mutmut run failed ({proc.returncode}):\n{out}")

    # mutmut 3 prints survivors in results; treat non-zero as fail above.
    # Soft check: no "survived" count in a failure-oriented summary if present.
    low = out.lower()
    if "survived" in low and "0 survived" not in low and "survived: 0" not in low:
        # Heuristic — CI job also checks mutmut results explicitly.
        if any(tok in low for tok in ("survived mutants", " mutants survived", "survivor")):
            pytest.fail(f"mutmut reported survivors:\n{out}")
