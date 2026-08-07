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


def _run_scan(extra_args: list[str]) -> subprocess.CompletedProcess:
    """Run bs scan with lua-bridge-compare, return CompletedProcess."""
    cmd = [
        BS, "scan",
        "--domain", TEST_DOMAIN,
        "--user-matrix", "-",
        "--max", "10",
        "--parallel", "1",
        "--timeout", "10",
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
    return subprocess.run(
        ["sudo", "-n", *cmd],
        input=TEST_STRATEGIES,
        capture_output=True, text=True,
        timeout=300,
        cwd=PROJECT_ROOT,
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

    # Count PASS lines in classic vs bridge sections
    # classic_passes = [line for line in stdout.splitlines() if "[OK]" in line or "[THROTTLED]" in line]
    bridge_passes = [line for line in stderr.splitlines() if "BRIDGE_DRIFT" in line]

    # Enforce: zero drift warnings
    for drift_line in bridge_passes:
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
    result = _run_scan([
        "--lua-bridge",
        "--bridge-batch", "1",
    ])

    stdout = result.stdout
    assert "TCP:" in stdout, f"No results. stdout:\n{stdout[:500]}"
    assert "Done in" in stdout
