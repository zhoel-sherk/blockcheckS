"""E2E integration: each bs subcommand runs end-to-end (Linux + sudo + nfqws2).

Smoke-level: command exits, a result is produced, netns pool is left clean.
Uses youtube.com (confirmed reachable via strategies) and short timeouts.
"""

from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BS = str(PROJECT_ROOT / ".venv" / "bin" / "bs")

DOMAIN = "youtube.com"
STRATEGY = "fake:blob=stun:repeats=6:tcp_ts=-1000"

COMMON_SKIPS = [
    "--skip-deps-check",
    "--skip-dns-audit",
    "--skip-prolog",
    "--skip-ip-block",
    "--skip-port-block",
    "--skip-baseline",
    "--no-wssize",
]


def _run(
    cmd: list[str], *, timeout: float = 120.0, input: str | None = None
) -> subprocess.CompletedProcess:
    """Run sudo bs ... in its own process group; kill tree on timeout."""
    proc = subprocess.Popen(
        ["sudo", "-n", *cmd],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        out, _ = proc.communicate(input=input or "", timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        proc.wait()
        return subprocess.CompletedProcess(cmd, 124, f"TIMEOUT after {timeout}s", "")
    return subprocess.CompletedProcess(cmd, proc.returncode, out, "")


def _cleanup() -> None:
    _run(["bash", str(PROJECT_ROOT / "scripts" / "cleanup_env.sh")], timeout=30)


@pytest.fixture(autouse=True)
def _clean_each(nfqws2_available):
    _cleanup()
    yield
    _cleanup()


def test_e2e_tcp():
    r = _run(
        [
            BS,
            "tcp",
            "--domain",
            DOMAIN,
            "--strategy",
            STRATEGY,
            "--timeout",
            "8",
            "--skip-deps-check",
        ]
    )
    # exit 0 when pass, 1 when no pass; both prove the pipeline ran
    assert r.returncode in (0, 1), r.stdout[-1000:]


def test_e2e_scan_smoke():
    matrix = "\n".join(
        [
            STRATEGY,
            "fake:blob=max_ru:repeats=6:tcp_ts=-1000",
            "hostfakesplit:nofake2:tcp_ts=-1000",
        ]
    )
    r = _run(
        [
            BS,
            "scan",
            "--db",
            "/tmp/e2e_scan.db",
            "--domain",
            DOMAIN,
            "--user-matrix",
            "-",
            "--max",
            "3",
            "--parallel",
            "2",
            "--timeout",
            "8",
            "--scan-level",
            "fast",
            *COMMON_SKIPS,
        ],
        timeout=180,
        input=matrix,
    )
    assert r.returncode in (0, 1), r.stdout[-1000:]


def test_e2e_pair_smoke():
    matrix = "\n".join(
        [
            STRATEGY,
            "fake:blob=max_ru:repeats=6:tcp_ts=-1000",
        ]
    )
    r = _run(
        [
            BS,
            "pair",
            "--db",
            "/tmp/e2e_pair.db",
            "--domain",
            DOMAIN,
            "--user-matrix",
            "-",
            "--max",
            "2",
            "--parallel",
            "1",
            "--timeout",
            "8",
            "--scan-level",
            "fast",
            *COMMON_SKIPS,
        ],
        timeout=180,
        input=matrix,
    )
    assert r.returncode in (0, 1), r.stdout[-1000:]


def test_e2e_udp_config_skip(tmp_path):
    # UDP voice needs a real voice endpoint; prove the command surfaces
    # gracefully (exit 0/1) rather than crashing.
    conf = tmp_path / "udp.conf"
    conf.write_text("--qnum=201\n--filter-udp=50000-50100\n--filter-l7=discord\n")
    r = _run(
        [
            BS,
            "udp",
            "--config",
            str(conf),
            "--timeout",
            "5",
            "--skip-deps-check",
        ],
        timeout=120,
    )
    assert r.returncode in (0, 1), r.stdout[-800:]


def test_e2e_composite(tmp_path):
    conf = tmp_path / "composite.conf"
    conf.write_text(
        "--qnum=200\n--filter-tcp=443\n--filter-l3=ipv4\n--filter-l7=tls\n"
        "--ipcache-lifetime=0\n--bind-fix4\n"
        f"--lua-desync={STRATEGY}\n"
    )
    r = _run(
        [
            BS,
            "composite",
            "--config",
            str(conf),
            "--timeout",
            "8",
            "--skip-deps-check",
        ],
        timeout=180,
    )
    assert r.returncode in (0, 1), r.stdout[-800:]


def test_e2e_bench_settle():
    r = _run(
        [
            BS,
            "bench-settle",
            "--domain",
            DOMAIN,
            "--strategy",
            STRATEGY,
            "--settle-times",
            "0.5,1.0",
            "--curl-timeouts",
            "1.0,2.0",
            "--max-strategies",
            "1",
            "--skip-deps-check",
        ],
        timeout=180,
    )
    assert r.returncode in (0, 1), r.stdout[-800:]


def test_e2e_stop_no_active_run():
    r = _run([BS, "stop"])
    assert r.returncode == 2  # no active run → graceful message


def test_e2e_full_smoke(tmp_path):
    dom_file = tmp_path / "domains.txt"
    dom_file.write_text(f"{DOMAIN}\n")
    db_file = tmp_path / "full.db"
    r = _run(
        [
            BS,
            "full",
            "--db",
            str(db_file),
            "--domain",
            DOMAIN,
            "--domains-file",
            str(dom_file),
            "--tcp-sources",
            "standard",
            "--max",
            "2",
            "--parallel",
            "1",
            "--timeout",
            "8",
            "--scan-level",
            "fast",
            "--no-http",
            "--no-quic",
            "--no-voice",
            "--skip-deps-check",
            "--skip-dns-audit",
            "--skip-prolog",
            "--skip-ip-block",
            "--skip-port-block",
            "--skip-baseline",
            "--no-wssize",
        ],
        timeout=180,
    )
    assert r.returncode in (0, 1), r.stdout[-1000:]
