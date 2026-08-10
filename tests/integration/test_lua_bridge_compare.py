"""Integration tests: lua_bridge vs classic verdict parity."""

from __future__ import annotations

import subprocess

import pytest
from tests.unit._quality_config import PROJECT_ROOT

pytestmark = [pytest.mark.integration, pytest.mark.slow]

BS = str(PROJECT_ROOT / ".venv" / "bin" / "bs")
TEST_STRATEGIES = "\n".join([
    "fake:blob=stun:repeats=6:tcp_ts=-1000",
    "fake:blob=max_ru:repeats=6:tcp_ts=-1000",
    "fake:blob=google:repeats=6:tcp_ts=-1000",
    "hostfakesplit:nofake2:repeats=1",
    "hostfakesplit:nofake2:tcp_md5:repeats=1",
    "hostfakesplit:disorder_after:nofake2:tcp_ack=-6600",
    "fake:blob=stun:repeats=8:tcp_ts=-1000",
    "fake:blob=max_ru:repeats=8:tcp_ts=-1000",
    "hostfakesplit:nofake2:tcp_ts=-1000:repeats=1",
    "fake:blob=4pda:repeats=6:tcp_ts=-1000",
])

TEST_DOMAIN = "discord.com"


def _run_scan(extra_args: list[str], *, max_strategies: int = 10) -> subprocess.CompletedProcess:
    """Run bs scan with lua-bridge-compare, return CompletedProcess.

    Runs the child in its own process group so that a subprocess timeout can
    kill the whole tree (sudo -> bs -> nfqws2). On Fryazino the per-strategy
    ``--timeout 5`` keeps FAIL paths short; ``--lua-bridge-compare`` doubles
    the work (classic + bridge), so the wall budget is generous.
    """
    cmd = [
        BS, "scan",
        "--domain", TEST_DOMAIN,
        "--user-matrix", "-",
        "--max", str(max_strategies),
        "--parallel", "1",
        "--timeout", "5",
        "--scan-level", "fast",
        "--skip-deps-check",
        "--skip-dns-audit",
        "--skip-prolog",
        "--skip-ip-block",
        "--skip-port-block",
        "--skip-baseline",
        "--no-wssize",
        *extra_args,
    ]
    import os
    import signal as _signal

    proc = subprocess.Popen(
        ["sudo", "-n", *cmd],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=PROJECT_ROOT,
        start_new_session=True,
    )
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    try:
        out, err = proc.communicate(input=TEST_STRATEGIES, timeout=500)
    except subprocess.TimeoutExpired:
        # sudo does not propagate SIGTERM down the tree: kill the whole process
        # group so bs + nfqws2 (and any stale run.lock) do not leak onwards.
        try:
            os.killpg(proc.pid, _signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        raise
    return subprocess.CompletedProcess(
        proc.args, proc.returncode or 0, out, err
    )


@pytest.mark.slow
def test_lua_bridge_compare_no_drift():
    """Verdict parity: classic PASS == bridge PASS for all strategy×domain pairs."""
    result = _run_scan([
        "--lua-bridge-compare",
        "--bridge-batch", "5",
    ])

    if result.returncode != 0 and result.returncode != 1:
        pytest.fail(f"scan failed (rc={result.returncode}):\n{result.stderr[:500]}")

    stdout = result.stdout
    stderr = result.stderr

    drift_lines = [line for line in stderr.splitlines() if "BRIDGE_DRIFT" in line]

    # Enforce: zero drift warnings
    for drift_line in drift_lines:
        if "DRIFT" in drift_line:
            pytest.fail(f"LUA BRIDGE DRIFT detected:\n{drift_line}")

    # Also check that both runs completed
    done_count = stdout.count("Done in")
    assert done_count >= 1, f"No scan completed. stdout:\n{stdout[:1000]}"
    assert done_count <= 2, f"Scan ran {done_count} times (expected 1-2). CliApp double-run?\n{stdout[:1000]}"


@pytest.mark.slow
def test_lua_bridge_batch_windows():
    """10 strategies, batch_size=3 → 4 windows. Verify all windows complete."""
    result = _run_scan([
        "--lua-bridge",
        "--bridge-batch", "3",
    ])

    stdout = result.stdout
    # Each bridge batch should produce at least one TCP result
    assert "TCP:" in stdout, f"No TCP results. stdout:\n{stdout[:500]}"
    assert "Done in" in stdout, f"Scan did not complete. stdout:\n{stdout[:500]}"
    assert stdout.count("Done in") == 1, f"Scan ran {stdout.count('Done in')} times — double-run?"


@pytest.mark.slow
def test_lua_bridge_batch_500_default():
    """10 strategies fit in one default batch=500 — one daemon boot."""
    result = _run_scan([
        "--lua-bridge",
        "--bridge-batch", "500",
    ])

    stdout = result.stdout
    assert "TCP:" in stdout
    assert "Done in" in stdout
    assert stdout.count("Done in") == 1


def test_lua_bridge_single_strategy():
    """Single strategy through bridge works."""
    result = _run_scan(
        ["--lua-bridge", "--bridge-batch", "1"],
        max_strategies=1,
    )

    stdout = result.stdout
    assert "TCP:" in stdout, f"No results. stdout:\n{stdout[:500]}"
    assert "Done in" in stdout
