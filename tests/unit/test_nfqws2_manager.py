"""Unit tests for Nfqws2Manager start/stop failure modes (mocked subprocess)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from blockchecks.service.nfqws2 import Nfqws2Manager

pytestmark = pytest.mark.unit


def test_start_config_missing_raises(tmp_path: Path):
    mgr = Nfqws2Manager(ns_name="bs-p0")
    with pytest.raises(FileNotFoundError, match="Config not found"):
        mgr.start_config(str(tmp_path / "missing.conf"))


def test_launch_raises_when_process_exits_immediately(tmp_path: Path):
    conf = tmp_path / "ok.conf"
    conf.write_text("--qnum=200\n--daemon\n", encoding="utf-8")

    dead = MagicMock()
    dead.pid = 4242
    dead.poll.return_value = 1  # exited

    mgr = Nfqws2Manager(ns_name="bs-p0")
    with (
        patch("blockchecks.service.nfqws2.get_nfqws2_bin", return_value="/opt/zapret2/nfq2/nfqws2"),
        patch("blockchecks.service.nfqws2.subprocess.Popen", return_value=dead),
        patch("blockchecks.service.nfqws2.wait_nfqws2_ready", return_value=0.01),
    ):
        with pytest.raises(RuntimeError, match="failed to start"):
            mgr.start_config(str(conf))
    assert mgr._proc is None
    assert mgr._pid is None


def test_launch_success_sets_pid(tmp_path: Path):
    conf = tmp_path / "ok.conf"
    conf.write_text("--qnum=200\n", encoding="utf-8")

    alive = MagicMock()
    alive.pid = 7777
    alive.poll.return_value = None

    mgr = Nfqws2Manager(ns_name="bs-p0")
    with (
        patch("blockchecks.service.nfqws2.get_nfqws2_bin", return_value="/bin/nfqws2"),
        patch("blockchecks.service.nfqws2.subprocess.Popen", return_value=alive) as popen,
        patch("blockchecks.service.nfqws2.wait_nfqws2_ready", return_value=0.02),
    ):
        mgr.start_config(str(conf))

    assert mgr._pid == 7777
    assert mgr._proc is alive
    cmd = popen.call_args.args[0]
    assert "netns" in cmd
    assert "bs-p0" in cmd
    assert any(str(a).startswith("@") for a in cmd)


def test_stop_killpg_and_unlinks_temps(tmp_path: Path):
    temp = tmp_path / "tmp.conf"
    temp.write_text("x", encoding="utf-8")

    mgr = Nfqws2Manager()
    mgr._pid = 9999
    mgr._proc = MagicMock()
    mgr._proc.wait.return_value = 0
    mgr._temp_files = [str(temp)]

    with (
        patch("blockchecks.service.nfqws2.os.getpgid", return_value=9999),
        patch("blockchecks.service.nfqws2.os.killpg") as killpg,
        patch("blockchecks.service.nfqws2.time.sleep"),
    ):
        mgr.stop()

    assert killpg.called
    assert mgr._pid is None
    assert mgr._proc is None
    assert mgr._temp_files == []
    assert not temp.exists()


def test_stop_handles_dead_pid(tmp_path):
    """H8: stop() must not raise when getpgid/killpg fail for an already-dead pid."""
    temp = tmp_path / "dead.conf"
    temp.write_text("x", encoding="utf-8")

    mgr = Nfqws2Manager()
    mgr._pid = 424242  # likely nonexistent
    mgr._proc = None
    mgr._temp_files = [str(temp)]

    with (
        patch("blockchecks.service.nfqws2.os.getpgid", side_effect=ProcessLookupError()),
        patch("blockchecks.service.nfqws2.time.sleep"),
    ):
        mgr.stop()  # must not raise

    assert mgr._pid is None
    assert mgr._temp_files == []
    assert not temp.exists()
