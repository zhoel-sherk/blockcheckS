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
    """Run mutmut and fail on any surviving mutant.

    mutmut 3.7.0 exits 0 even when mutants survive (status is printed via
    emoji + a summary), so parsing stdout is unreliable. After a run it writes
    ``mutants/mutmut-cicd-stats.json`` with explicit ``survived``/``killed``/
    ``total``/``no_tests`` counters — that is the stable CI contract we gate on.
    """
    import json

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
        # mutmut exits 4 (usage error) when its internal pytest invocation
        # breaks — typically a version incompatibility (mutmut 3.7 vs pytest 9)
        # surfacing as BadTestExecutionCommandsException, or a stale
        # pytest_add_cli_args_test_selection with a bare "-m" that collides
        # with [tool.pytest.ini_options].addopts. Surface a targeted message.
        if proc.returncode == 4 and "BadTestExecutionCommandsException" in out:
            pytest.fail(
                "mutmut run failed with exit 4 (pytest usage error):\n"
                f"{out[-2000:]}\n\n"
                "Likely mutmut 3.7 vs pytest 9 incompatibility, or a duplicate "
                "'-m' in [tool.mutmut].pytest_add_cli_args_test_selection vs "
                "[tool.pytest.ini_options].addopts. See changelog 1.3.6."
            )
        pytest.fail(f"mutmut run failed ({proc.returncode}):\n{out}")

    stats_path = PROJECT_ROOT / "mutants" / "mutmut-cicd-stats.json"
    if not stats_path.is_file():
        pytest.fail(
            f"mutmut did not write {stats_path} (run aborted early?). stdout tail:\n{out[-2000:]}"
        )
    stats = json.loads(stats_path.read_text(encoding="utf-8"))
    survived = int(stats.get("survived") or 0)
    total = int(stats.get("total") or 0)
    killed = int(stats.get("killed") or 0)
    no_tests = int(stats.get("no_tests") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    if survived:
        pytest.fail(
            f"mutmut: {survived} survivors out of {total} mutants "
            f"(killed={killed}, no_tests={no_tests}, suspicious={suspicious}). "
            f"See 'mutmut results' and 'mutants/' for details."
        )
    # Sanity: the run must have actually executed mutants.
    if total <= 0:
        pytest.fail(f"mutmut reported total={total}; no mutants were checked.")
