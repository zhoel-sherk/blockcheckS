"""Unit tests for Nfqws2Launcher (daemon + foreground, mocked subprocess)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from blockchecks.service.nfqws2_launcher import Nfqws2Launcher, start_daemon

pytestmark = pytest.mark.unit


def test_foreground_success_resolves_real_pid(tmp_path: Path):
    conf = tmp_path / "ok.conf"
    conf.write_text("--qnum=200\n", encoding="utf-8")

    alive = MagicMock()
    alive.pid = 7777
    alive.poll.return_value = None

    launcher = Nfqws2Launcher(ns_name="bs-p0")
    with (
        patch("blockchecks.service.nfqws2_launcher.get_nfqws2_bin", return_value="/bin/nfqws2"),
        patch("blockchecks.service.nfqws2_launcher.subprocess.Popen", return_value=alive) as popen,
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_ready", return_value=0.02),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_bind_proof", return_value=True),
        patch(
            "blockchecks.service.nfqws2_launcher.resolve_nfqws2_pids",
            side_effect=[[], [1001]],
        ),
    ):
        result = launcher.foreground(f"@{conf}")

    assert result.pid == 1001
    assert result.proc is alive
    cmd = popen.call_args.args[0]
    assert "netns" in cmd
    assert "bs-p0" in cmd


def test_foreground_exits_immediately_raises(tmp_path: Path):
    conf = tmp_path / "ok.conf"
    conf.write_text("--qnum=200\n", encoding="utf-8")

    dead = MagicMock()
    dead.pid = 4242
    dead.poll.return_value = 1

    launcher = Nfqws2Launcher(ns_name="bs-p0")
    with (
        patch("blockchecks.service.nfqws2_launcher.get_nfqws2_bin", return_value="/bin/nfqws2"),
        patch("blockchecks.service.nfqws2_launcher.subprocess.Popen", return_value=dead),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_ready", return_value=0.01),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_bind_proof", return_value=True),
        patch("blockchecks.service.nfqws2_launcher.resolve_nfqws2_pids", return_value=[]),
    ):
        with pytest.raises(RuntimeError, match="failed to start"):
            launcher.foreground(f"@{conf}")


def test_daemon_launches_and_returns_settle(tmp_path: Path):
    conf = tmp_path / "c.conf"
    conf.write_text("--qnum=200\n")

    proc = MagicMock()
    proc.pid = 5555
    with (
        patch("blockchecks.service.nfqws2_launcher.subprocess.Popen", return_value=proc) as popen,
        patch("blockchecks.service.nfqws2_launcher.inject_debug_and_daemon", return_value=None),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_ready", return_value=0.5),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_bind_proof", return_value=True),
        patch("blockchecks.service.nfqws2_launcher._wait_nfqws2_gone", return_value=True),
        patch("blockchecks.service.nfqws2_launcher._reclaim_debug_log"),
        patch("blockchecks.service.nfqws2_launcher._reap_daemon_popens"),
        patch("blockchecks.service.nfqws2_launcher.resolve_nfqws2_pids", return_value=[9001]),
    ):
        settle = start_daemon("bs-p-0", str(conf))
    assert settle == 0.5
    assert popen.called


def test_daemon_requires_ns_name(tmp_path: Path):
    launcher = Nfqws2Launcher()
    with pytest.raises(ValueError, match="requires ns_name"):
        launcher.daemon(str(tmp_path / "c.conf"))
