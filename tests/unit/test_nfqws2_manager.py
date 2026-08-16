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


def test_start_full_cli_strategy_no_double_payload(tmp_path: Path):
    """A full CLI strategy (custom list_http.txt) is split as-is, not re-wrapped
    with --payload=tls_client_hello (which makes nfqws2 exit immediately)."""
    alive = MagicMock()
    alive.pid = 8888
    alive.poll.return_value = None

    mgr = Nfqws2Manager(ns_name="bs-p0")
    with (
        patch("blockchecks.service.nfqws2.get_nfqws2_bin", return_value="/bin/nfqws2"),
        patch("blockchecks.service.nfqws2.subprocess.Popen", return_value=alive) as popen,
        patch("blockchecks.service.nfqws2.wait_nfqws2_ready", return_value=0.02),
    ):
        mgr.start("--payload=http_req --lua-desync=http_hostcase")

    cmd = popen.call_args.args[0]
    conf_arg = next(str(a) for a in cmd if str(a).startswith("@"))
    conf_text = Path(conf_arg[1:]).read_text(encoding="utf-8")
    assert "--payload=http_req" in conf_text
    assert "--lua-desync=http_hostcase" in conf_text
    assert "--payload=tls_client_hello" not in conf_text


def test_start_simple_strategy_still_wrapped(tmp_path: Path):
    """Plain fake:... strategies keep the default TLS payload + lua-desync wrap."""
    alive = MagicMock()
    alive.pid = 9999
    alive.poll.return_value = None

    mgr = Nfqws2Manager(ns_name="bs-p0")
    with (
        patch("blockchecks.service.nfqws2.get_nfqws2_bin", return_value="/bin/nfqws2"),
        patch("blockchecks.service.nfqws2.subprocess.Popen", return_value=alive) as popen,
        patch("blockchecks.service.nfqws2.wait_nfqws2_ready", return_value=0.02),
    ):
        mgr.start("fake:blob=stun:repeats=6:tcp_ts=-1000")

    cmd = popen.call_args.args[0]
    conf_arg = next(str(a) for a in cmd if str(a).startswith("@"))
    conf_text = Path(conf_arg[1:]).read_text(encoding="utf-8")
    assert "--payload=tls_client_hello" in conf_text
    assert "--lua-desync=fake:blob=stun:repeats=6:tcp_ts=-1000" in conf_text


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


# ── added: inject_debug / start_daemon / launch branches / hostlist / stop ─


def test_inject_debug_and_daemon_adds_both(tmp_path):
    from blockchecks.service.nfqws2 import inject_debug_and_daemon

    conf = tmp_path / "c.conf"
    conf.write_text("--qnum=200\n")
    with patch("blockchecks.service.nfqws2.nfqws2_debug_conf_line",
               return_value=("--debug=@/tmp/dbg.log", "/tmp/dbg.log")):
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
    with patch("blockchecks.service.nfqws2.nfqws2_debug_conf_line",
               return_value=(None, None)):
        log = inject_debug_and_daemon(str(conf), tag="t")
    assert log is None
    # unchanged
    assert "--daemon" in conf.read_text()


def test_start_daemon_launches(tmp_path):

    from blockchecks.service.nfqws2 import start_daemon

    conf = tmp_path / "c.conf"
    conf.write_text("--qnum=200\n")
    with patch("blockchecks.service.nfqws2.subprocess.run"), patch(
        "blockchecks.service.nfqws2.subprocess.Popen"
    ), patch("blockchecks.service.nfqws2.inject_debug_and_daemon",
             return_value=(None, None)), patch(
        "blockchecks.service.nfqws2.wait_nfqws2_ready", return_value=0.5
    ), patch("blockchecks.service.nfqws2._wait_nfqws2_gone",
             return_value=True), patch(
        "blockchecks.service.nfqws2._reclaim_debug_log"):
        settle = start_daemon("bs-p-0", str(conf))
    assert settle == 0.5


def test_launch_sudo_no_netns(tmp_path):
    mgr = Nfqws2Manager()  # no ns → sudo -n without netns exec
    proc = MagicMock()
    proc.poll.return_value = None
    proc.pid = 123
    with patch("blockchecks.service.nfqws2.get_nfqws2_bin",
               return_value="/x/nfqws2"), patch(
        "blockchecks.service.nfqws2.subprocess.Popen", return_value=proc
    ), patch("blockchecks.service.nfqws2.time.sleep"), patch(
        "blockchecks.service.nfqws2._reclaim_debug_log"):
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
    with patch("blockchecks.service.nfqws2.get_nfqws2_bin",
               return_value="/x/nfqws2"), patch(
        "blockchecks.service.nfqws2.subprocess.Popen", return_value=proc
    ), patch("blockchecks.service.nfqws2.wait_nfqws2_ready"), patch(
        "blockchecks.service.nfqws2._reclaim_debug_log"):
        with pytest.raises(RuntimeError, match="failed to start"):
            mgr._launch("@/tmp/x.conf")


def test_start_with_hostlist(tmp_path):
    mgr = Nfqws2Manager()
    proc = MagicMock()
    proc.poll.return_value = None
    proc.pid = 55
    with patch("blockchecks.service.nfqws2.get_nfqws2_bin",
               return_value="/x/nfqws2"), patch(
        "blockchecks.service.nfqws2.subprocess.Popen", return_value=proc
    ), patch("blockchecks.service.nfqws2.wait_nfqws2_ready"), patch(
        "blockchecks.service.nfqws2._reclaim_debug_log"), patch(
        "blockchecks.service.nfqws2.nfqws2_debug_conf_line",
        return_value=(None, None)), patch(
        "blockchecks.service.nfqws2.get_lua_init_scripts", return_value=[]
    ), patch("blockchecks.service.nfqws2.BLOB_DIR", str(tmp_path)), patch(
        "blockchecks.engine.blob_aliases.append_blob_cli_lines"), patch(
        "blockchecks.engine.blob_aliases.extract_blob_names", return_value=[]
    ):
        mgr.start("fake:blob=stun", hostlist=["discord.com"], qnum=200)
    assert mgr._pid == 55
    assert len(mgr._temp_files) == 2  # hostlist + conf
    mgr.stop()


def test_context_manager_stops():
    mgr = Nfqws2Manager()
    with patch.object(mgr, "stop") as stop:
        with mgr:
            pass
    stop.assert_called_once()


def test_stop_killpg_exception_handled():
    mgr = Nfqws2Manager()
    mgr._pid = 12345
    mgr._proc = MagicMock()
    with patch("blockchecks.service.nfqws2.os.killpg",
               side_effect=ProcessLookupError), patch(
        "blockchecks.service.nfqws2.os.getpgid", return_value=999), patch(
        "blockchecks.service.nfqws2.os.unlink"):
        mgr.stop()  # must not raise
    assert mgr._pid is None


def test_reclaim_debug_log(tmp_path):
    from blockchecks.service.nfqws2 import _reclaim_debug_log

    with patch("blockchecks.engine.paths.reclaim_sudo_ownership") as rc:
        _reclaim_debug_log(str(tmp_path / "dbg.log"))
    rc.assert_called_once()
    _reclaim_debug_log(None)  # no-op
