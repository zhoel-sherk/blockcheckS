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
        patch("blockchecks.service.nfqws2_launcher.get_nfqws2_bin", return_value="/opt/zapret2/nfq2/nfqws2"),
        patch("blockchecks.service.nfqws2_launcher.subprocess.Popen", return_value=dead),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_ready", return_value=0.01),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_bind_proof", return_value=True),
        patch("blockchecks.service.nfqws2_launcher.resolve_nfqws2_pids", return_value=[]),
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
        patch("blockchecks.service.nfqws2_launcher.get_nfqws2_bin", return_value="/bin/nfqws2"),
        patch("blockchecks.service.nfqws2_launcher.subprocess.Popen", return_value=alive) as popen,
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_ready", return_value=0.02),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_bind_proof", return_value=True),
        patch(
            "blockchecks.service.nfqws2_launcher.resolve_nfqws2_pids",
            side_effect=[[], [1001]],
        ),
    ):
        mgr.start_config(str(conf))

    assert mgr._pid == 1001  # real nfqws2, not sudo Popen 7777
    assert mgr._proc is alive
    cmd = popen.call_args.args[0]
    assert "netns" in cmd
    assert "bs-p0" in cmd
    assert any(str(a).startswith("@") for a in cmd)


def test_start_full_cli_strategy_no_double_payload(tmp_path: Path):
    """A full CLI strategy (custom list_http.txt) is split as-is, not re-wrapped
    with --payload=tls_client_hello (which makes nfqws2 exit immediately)."""
    alive = MagicMock()
    alive.pid = 8888
    alive.poll.return_value = None

    mgr = Nfqws2Manager(ns_name="bs-p0")
    with (
        patch("blockchecks.service.nfqws2_launcher.get_nfqws2_bin", return_value="/bin/nfqws2"),
        patch("blockchecks.service.nfqws2_launcher.subprocess.Popen", return_value=alive) as popen,
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_ready", return_value=0.02),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_bind_proof", return_value=True),
        patch("blockchecks.service.nfqws2_launcher.resolve_nfqws2_pids", return_value=[1001]),
    ):
        mgr.start("--payload=http_req --lua-desync=http_hostcase")

    cmd = popen.call_args.args[0]
    conf_arg = next(str(a) for a in cmd if str(a).startswith("@"))
    conf_text = Path(conf_arg[1:]).read_text(encoding="utf-8")
    assert "--payload=http_req" in conf_text
    assert "--lua-desync=http_hostcase" in conf_text
    assert "--payload=tls_client_hello" not in conf_text


def test_start_renames_digit_leading_blob(tmp_path: Path):
    """4pda must become b4pda in conf (nfqws2 fatal on leading-digit blob ids)."""
    blobs = tmp_path / "blobs"
    blobs.mkdir()
    (blobs / "tls_clienthello_4pda_to.bin").write_bytes(b"x" * 8)

    alive = MagicMock()
    alive.pid = 9999
    alive.poll.return_value = None

    mgr = Nfqws2Manager(ns_name="bs-p0")
    with (
        patch("blockchecks.service.nfqws2_launcher.get_nfqws2_bin", return_value="/bin/nfqws2"),
        patch("blockchecks.service.nfqws2_launcher.subprocess.Popen", return_value=alive) as popen,
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_ready", return_value=0.02),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_bind_proof", return_value=True),
        patch("blockchecks.service.nfqws2_launcher.resolve_nfqws2_pids", return_value=[1001]),
        patch("blockchecks.service.nfqws2.BLOB_DIR", str(blobs)),
    ):
        mgr.start("fake:blob=4pda:repeats=6:tcp_ts=-1000")

    cmd = popen.call_args.args[0]
    conf_arg = next(str(a) for a in cmd if str(a).startswith("@"))
    conf_text = Path(conf_arg[1:]).read_text(encoding="utf-8")
    assert "--blob=b4pda:@" in conf_text
    assert "--lua-desync=fake:blob=b4pda:repeats=6:tcp_ts=-1000" in conf_text
    assert "blob=4pda" not in conf_text


def test_start_simple_strategy_still_wrapped(tmp_path: Path):
    """Plain fake:... strategies keep the default TLS payload + lua-desync wrap."""
    alive = MagicMock()
    alive.pid = 9999
    alive.poll.return_value = None

    mgr = Nfqws2Manager(ns_name="bs-p0")
    with (
        patch("blockchecks.service.nfqws2_launcher.get_nfqws2_bin", return_value="/bin/nfqws2"),
        patch("blockchecks.service.nfqws2_launcher.subprocess.Popen", return_value=alive) as popen,
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_ready", return_value=0.02),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_bind_proof", return_value=True),
        patch("blockchecks.service.nfqws2_launcher.resolve_nfqws2_pids", return_value=[1001]),
    ):
        mgr.start("fake:blob=stun:repeats=6:tcp_ts=-1000")

    cmd = popen.call_args.args[0]
    conf_arg = next(str(a) for a in cmd if str(a).startswith("@"))
    conf_text = Path(conf_arg[1:]).read_text(encoding="utf-8")
    assert "--payload=tls_client_hello" in conf_text
    assert "--lua-desync=fake:blob=stun:repeats=6:tcp_ts=-1000" in conf_text


def test_stop_pkill_in_ns_and_unlinks_temps(tmp_path: Path):
    temp = tmp_path / "tmp.conf"
    temp.write_text("x", encoding="utf-8")

    mgr = Nfqws2Manager(ns_name="bs-p0")
    mgr._pid = 9999
    mgr._proc = MagicMock()
    mgr._proc.wait.return_value = 0
    mgr._temp_files = [str(temp)]

    with patch("blockchecks.service.metrics.pkill_nfqws2_in_ns") as pkill:
        mgr.stop()

    pkill.assert_called_once_with("bs-p0")
    assert mgr._pid is None
    assert mgr._proc is None
    assert mgr._temp_files == []
    assert not temp.exists()


def test_stop_sudo_kill_host_pid(tmp_path: Path):
    mgr = Nfqws2Manager()
    mgr._pid = 9999
    mgr._proc = MagicMock()
    mgr._proc.wait.return_value = 0

    with patch("blockchecks.service.metrics._kill_pid_sigkill") as kill:
        mgr.stop()

    kill.assert_called_once_with(9999)
    assert mgr._pid is None


def test_stop_handles_dead_pid(tmp_path):
    """Stop() must not raise when PID-scope kill fails for an already-dead pid."""
    temp = tmp_path / "dead.conf"
    temp.write_text("x", encoding="utf-8")

    mgr = Nfqws2Manager()
    mgr._pid = 424242  # likely nonexistent
    mgr._proc = None
    mgr._temp_files = [str(temp)]

    with patch("blockchecks.service.metrics._kill_pid_sigkill", return_value=False):
        mgr.stop()  # must not raise

    assert mgr._pid is None
    assert mgr._temp_files == []
    assert not temp.exists()


# inject_debug / start_daemon / launch branches / hostlist / stop
def test_inject_debug_and_daemon_adds_both(tmp_path):
    from blockchecks.service.nfqws2 import inject_debug_and_daemon

    conf = tmp_path / "c.conf"
    conf.write_text("--qnum=200\n")
    with patch(
        "blockchecks.service.nfqws2_launcher.nfqws2_debug_conf_line",
        return_value=("--debug=@/tmp/dbg.log", "/tmp/dbg.log"),
    ):
        log = inject_debug_and_daemon(str(conf), tag="t")
    text = conf.read_text()
    assert "--daemon" in text
    assert "--debug=" in text
    assert log == "/tmp/dbg.log"


def test_inject_debug_missing_file():
    from blockchecks.service.nfqws2 import inject_debug_and_daemon

    assert inject_debug_and_daemon("/nonexistent.conf") is None


def test_inject_debug_already_has_daemon(tmp_path):
    from blockchecks.service.nfqws2 import inject_debug_and_daemon

    conf = tmp_path / "c.conf"
    conf.write_text("--daemon\n--qnum=200\n")
    with patch("blockchecks.service.nfqws2_launcher.nfqws2_debug_conf_line", return_value=(None, None)):
        log = inject_debug_and_daemon(str(conf), tag="t")
    assert log is None
    # unchanged
    assert "--daemon" in conf.read_text()


def test_start_daemon_launches(tmp_path):

    from blockchecks.service.nfqws2 import start_daemon

    conf = tmp_path / "c.conf"
    conf.write_text("--qnum=200\n")
    with (
        patch("blockchecks.service.nfqws2_launcher.subprocess.Popen") as popen,
        patch("blockchecks.service.nfqws2_launcher.inject_debug_and_daemon", return_value=None),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_ready", return_value=0.5),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_bind_proof", return_value=True),
        patch("blockchecks.service.nfqws2_launcher._wait_nfqws2_gone", return_value=True),
        patch("blockchecks.service.nfqws2_launcher._reclaim_debug_log"),
        patch("blockchecks.service.nfqws2_launcher._reap_daemon_popens"),
        patch("blockchecks.service.nfqws2_launcher.resolve_nfqws2_pids", return_value=[9001]),
    ):
        proc = MagicMock()
        proc.pid = 5555
        popen.return_value = proc
        settle = start_daemon("bs-p-0", str(conf))
    assert settle == 0.5
    assert popen.called


def test_start_daemon_tracks_popen_for_reap(tmp_path):
    import blockchecks.service.nfqws2_launcher as launcher_mod

    conf = tmp_path / "c.conf"
    conf.write_text("--qnum=200\n")
    proc = MagicMock()
    proc.pid = 6001
    proc.poll.return_value = 0

    with (
        patch.object(launcher_mod.subprocess, "Popen", return_value=proc),
        patch.object(launcher_mod, "inject_debug_and_daemon", return_value=None),
        patch.object(launcher_mod, "wait_nfqws2_ready", return_value=0.01),
        patch.object(launcher_mod, "wait_nfqws2_bind_proof", return_value=True),
        patch.object(launcher_mod, "_wait_nfqws2_gone", return_value=True),
        patch.object(launcher_mod, "_reclaim_debug_log"),
        patch.object(launcher_mod, "open_out_capture", return_value=(None, None)),
        patch.object(launcher_mod, "resolve_nfqws2_pids", return_value=[9001]),
    ):
        launcher_mod._daemon_popens.clear()
        launcher_mod.start_daemon("bs-p-0", str(conf), kill_existing=False)
    assert proc in launcher_mod._daemon_popens
    launcher_mod._reap_daemon_popens()
    proc.poll.assert_called()


def test_start_daemon_warns_when_drain_times_out(tmp_path, caplog):
    import logging

    import blockchecks.service.nfqws2_launcher as launcher_mod

    conf = tmp_path / "c.conf"
    conf.write_text("--qnum=200\n")
    proc = MagicMock()
    proc.pid = 6002
    with (
        patch.object(launcher_mod.subprocess, "Popen", return_value=proc),
        patch.object(launcher_mod, "inject_debug_and_daemon", return_value=None),
        patch.object(launcher_mod, "wait_nfqws2_ready", return_value=0.01),
        patch.object(launcher_mod, "wait_nfqws2_bind_proof", return_value=True),
        patch.object(launcher_mod, "_wait_nfqws2_gone", return_value=False),
        patch("blockchecks.service.metrics.pkill_nfqws2_in_ns"),
        patch.object(launcher_mod, "_reclaim_debug_log"),
        patch.object(launcher_mod, "open_out_capture", return_value=(None, None)),
        patch.object(launcher_mod, "resolve_nfqws2_pids", return_value=[9001]),
        caplog.at_level(logging.WARNING),
    ):
        launcher_mod.start_daemon("bs-p-0", str(conf), kill_existing=True)
    assert "pkill drain" in caplog.text


def test_launch_settle_timeout_raises_when_no_procs(tmp_path):
    conf = tmp_path / "ok.conf"
    conf.write_text("--qnum=200\n", encoding="utf-8")

    alive = MagicMock()
    alive.pid = 7777
    alive.poll.return_value = None

    mgr = Nfqws2Manager(ns_name="bs-p0")
    with (
        patch("blockchecks.service.nfqws2_launcher.get_nfqws2_bin", return_value="/bin/nfqws2"),
        patch("blockchecks.service.nfqws2_launcher.subprocess.Popen", return_value=alive),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_ready", return_value=0.6),
        patch("blockchecks.service.nfqws2_launcher.NFQWS2_SETTLE_MAX", 0.5),
        patch("blockchecks.service.nfqws2_launcher.nfqws2_count_in_ns", return_value=0),
        patch("blockchecks.service.nfqws2_launcher.nfqws2_out_shows_bind", return_value=False),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_bind_proof", return_value=True),
    ):
        with pytest.raises(RuntimeError, match="not visible"):
            mgr.start_config(str(conf))


def test_launch_settle_skips_visibility_raise_when_bind_marker(tmp_path):
    conf = tmp_path / "ok.conf"
    conf.write_text("--qnum=200\n", encoding="utf-8")

    alive = MagicMock()
    alive.pid = 7777
    alive.poll.return_value = None

    mgr = Nfqws2Manager(ns_name="bs-p0")
    with (
        patch("blockchecks.service.nfqws2_launcher.get_nfqws2_bin", return_value="/bin/nfqws2"),
        patch("blockchecks.service.nfqws2_launcher.subprocess.Popen", return_value=alive),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_ready", return_value=0.6),
        patch("blockchecks.service.nfqws2_launcher.NFQWS2_SETTLE_MAX", 0.5),
        patch("blockchecks.service.nfqws2_launcher.nfqws2_count_in_ns", return_value=0),
        patch("blockchecks.service.nfqws2_launcher.nfqws2_out_shows_bind", return_value=True),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_bind_proof", return_value=True),
        patch("blockchecks.service.nfqws2_launcher.resolve_nfqws2_pids", return_value=[]),
        patch("blockchecks.service.nfqws2_launcher._reclaim_debug_log"),
        patch("blockchecks.service.nfqws2_launcher.open_out_capture", return_value=(None, None)),
    ):
        mgr.start_config(str(conf))
    assert mgr._pid == 7777  # EPERM: no comm=nfqws2 visible; keep wrapper pid


def test_launch_sudo_no_netns(tmp_path):
    mgr = Nfqws2Manager()  # no ns → sudo -n without netns exec
    proc = MagicMock()
    proc.poll.return_value = None
    proc.pid = 123
    with (
        patch("blockchecks.service.nfqws2_launcher.get_nfqws2_bin", return_value="/x/nfqws2"),
        patch("blockchecks.service.nfqws2_launcher.subprocess.Popen", return_value=proc),
        patch("blockchecks.service.nfqws2_launcher.time.sleep"),
        patch("blockchecks.service.nfqws2_launcher._reclaim_debug_log"),
    ):
        mgr._launch("@/tmp/x.conf")
    assert mgr._pid == 123


def test_launch_failure_debug_tail(tmp_path):
    mgr = Nfqws2Manager()
    proc = MagicMock()
    proc.poll.return_value = 1  # exited
    proc.pid = 123
    dbg = tmp_path / "dbg.log"
    dbg.write_text("error: failed")
    mgr.last_debug_log = str(dbg)
    with (
        patch("blockchecks.service.nfqws2_launcher.get_nfqws2_bin", return_value="/x/nfqws2"),
        patch("blockchecks.service.nfqws2_launcher.subprocess.Popen", return_value=proc),
        patch("blockchecks.service.nfqws2_launcher.wait_nfqws2_ready"),
        patch("blockchecks.service.nfqws2_launcher._reclaim_debug_log"),
    ):
        with pytest.raises(RuntimeError, match="failed to start"):
            mgr._launch("@/tmp/x.conf")


def test_start_with_hostlist(tmp_path):
    mgr = Nfqws2Manager()
    proc = MagicMock()
    proc.poll.return_value = None
    proc.pid = 55
    with (
        patch.object(mgr, "_launch") as mlaunch,
        patch("blockchecks.service.nfqws2_launcher.nfqws2_debug_conf_line", return_value=(None, None)),
        patch("blockchecks.service.nfqws2.get_lua_init_scripts", return_value=[]),
        patch("blockchecks.engine.blob_aliases.sanitize_strategy_for_nfqws2", return_value="fake:blob=stun"),
    ):
        mgr.start("fake:blob=stun", hostlist=["discord.com"], qnum=200)
    assert mlaunch.called
    assert len(mgr._temp_files) == 2  # hostlist + conf
    mgr.stop()


def test_context_manager_stops():
    mgr = Nfqws2Manager()
    with patch.object(mgr, "stop") as stop:
        with mgr:
            pass
    stop.assert_called_once()


def test_stop_kill_failure_handled():
    mgr = Nfqws2Manager()
    mgr._pid = 12345
    mgr._proc = MagicMock()
    with patch("blockchecks.service.metrics._kill_pid_sigkill", return_value=False):
        mgr.stop()  # must not raise
    assert mgr._pid is None


def test_reclaim_debug_log(tmp_path):
    from blockchecks.service.nfqws2 import _reclaim_debug_log

    with patch("blockchecks.engine.paths.reclaim_sudo_ownership") as rc:
        _reclaim_debug_log(str(tmp_path / "dbg.log"))
    rc.assert_called_once()
    _reclaim_debug_log(None)  # no-op


def test_open_out_capture_writes_header(tmp_path, monkeypatch):
    import blockchecks.service.nfqws2 as nfq

    monkeypatch.setattr("blockchecks.engine.paths.RUNTIME_LOGS_DIR", tmp_path)
    fh, path = nfq.open_out_capture("ns-t")
    assert fh is not None and path is not None
    fh.close()
    assert path.parent == tmp_path
    assert path.name.startswith("nfqws2_out_ns-t_")
    assert b"tag=ns-t" in path.read_bytes()


def test_open_out_capture_disabled_on_oserror(monkeypatch, caplog):
    import logging

    import blockchecks.service.nfqws2 as nfq

    class _NoDir:
        def mkdir(self, *a, **k):
            raise OSError("denied")

    monkeypatch.setattr("blockchecks.engine.paths.RUNTIME_LOGS_DIR", _NoDir())
    with caplog.at_level(logging.WARNING):
        fh, path = nfq.open_out_capture("ns-x")
    assert fh is None and path is None
    assert "out-capture disabled" in caplog.text
