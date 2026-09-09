"""Unit tests for blockchecks.service.lua_session (mocked nfqws2/iptables)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from blockchecks.engine.generators.base import StrategyItem
from blockchecks.service.lua_session import (
    BridgeSession,
    bridge_worker_session,
    strategy_text_from_item,
    teardown_all_bridge_shm,
)


@pytest.fixture
def session():
    bridge = MagicMock()
    bridge.paths.base = Path("/tmp/shm/bs-p0")
    return BridgeSession(
        ns_name="bs-p0",
        strategies=["fake:blob=stun:repeats=6:tcp_ts=-1000"],
        bridge=bridge,
    )


@pytest.mark.unit
def test_bridge_session_boot(session, tmp_path):
    conf = tmp_path / "old.conf"
    conf.write_text("--qnum=200\n", encoding="utf-8")
    session.conf_path = str(conf)

    with (
        patch("blockchecks.service.lua_session._check_netns_exists"),
        patch("blockchecks.service.lua_session.write_bridge_conf", return_value="/tmp/new.conf"),
        patch("blockchecks.service.nfqws2.start_daemon", return_value=0.1),
        patch("blockchecks.service.lua_session._bridge_iptables_add"),
    ):
        settle = session.boot()

    assert settle == 0.1
    assert session.iptables_ready is True
    assert session.conf_path == "/tmp/new.conf"
    session.bridge.setup.assert_called_once()


@pytest.mark.unit
def test_bridge_session_boot_iptables_fail_leaves_not_ready(session, tmp_path):
    from blockchecks.service.lua_netns import IptablesError

    with (
        patch("blockchecks.service.lua_session._check_netns_exists"),
        patch("blockchecks.service.lua_session.write_bridge_conf", return_value="/tmp/new.conf"),
        patch("blockchecks.service.nfqws2.start_daemon", return_value=0.1),
        patch(
            "blockchecks.service.lua_session._bridge_iptables_add",
            side_effect=IptablesError("nfq"),
        ),
        pytest.raises(IptablesError),
    ):
        session.boot()
    assert session.iptables_ready is False


@pytest.mark.unit
def test_bridge_session_shutdown(session):
    session.iptables_ready = True
    with patch("blockchecks.service.lua_session.os.unlink"):
        session.shutdown()
    assert session.iptables_ready is False
    session.bridge.teardown.assert_called_once()


@pytest.mark.unit
def test_strategy_text_from_item_inline():
    item = StrategyItem(label="fake", strategy="fake:blob=stun:repeats=6")
    assert strategy_text_from_item(item) == "fake:blob=stun:repeats=6"


@pytest.mark.unit
def test_strategy_text_from_item_config(tmp_path):
    conf = tmp_path / "s.conf"
    conf.write_text("--qnum=200\n--lua-desync=fake:blob=stun:repeats=6\n", encoding="utf-8")
    item = StrategyItem(label="cfg", strategy=str(conf), is_config=True)
    assert strategy_text_from_item(item) == "fake:blob=stun:repeats=6"


@pytest.mark.unit
def test_teardown_all_bridge_shm_scoped_by_prefix(tmp_path):
    shm = tmp_path / "blockchecks"
    shm.mkdir(parents=True)
    own = shm / "bs-p-1234-0"
    other = shm / "bs-p-5678-0"
    own.mkdir()
    other.mkdir()
    (own / "x").write_text("", encoding="utf-8")
    (other / "y").write_text("", encoding="utf-8")

    teardown_all_bridge_shm(shm, pid=1234)

    assert not own.exists()
    assert other.is_dir()
    assert (other / "y").exists()


@pytest.mark.unit
def test_teardown_all_bridge_shm_by_ns_names(tmp_path):
    shm = tmp_path / "blockchecks"
    shm.mkdir(parents=True)
    a = shm / "bs-p-1234-0"
    b = shm / "bs-p-1234-1"
    c = shm / "bs-p-5678-0"
    for d in (a, b, c):
        d.mkdir()
        (d / "f").write_text("x", encoding="utf-8")

    teardown_all_bridge_shm(shm, ns_names=["bs-p-1234-0"])

    assert not a.exists()
    assert b.is_dir()
    assert c.is_dir()


@pytest.mark.unit
def test_teardown_all_bridge_shm_no_scope_warns(tmp_path, caplog):
    import logging

    shm = tmp_path / "blockchecks"
    shm.mkdir(parents=True)
    leftover = shm / "bs-p-1234-0"
    leftover.mkdir()

    with caplog.at_level(logging.WARNING):
        teardown_all_bridge_shm(shm)

    assert leftover.is_dir()
    assert "skipping SHM cleanup" in caplog.text


@pytest.mark.unit
def test_teardown_all_bridge_shm_missing(tmp_path):
    """teardown несуществующего каталога — no-op без исключений."""
    missing = tmp_path / "nope"
    teardown_all_bridge_shm(missing, pid=os.getpid())
    assert not missing.exists(), "не должен создаваться при teardown"


@pytest.mark.unit
def test_bridge_worker_session_context():
    with (
        patch("blockchecks.service.lua_session.BridgeSession") as m_cls,
        patch("blockchecks.service.lua_session.LuaBridge"),
    ):
        inst = m_cls.return_value
        inst.boot.return_value = 0.1
        with bridge_worker_session("bs-p0", ["fake:blob=stun:repeats=6"], protocol="tls12") as s:
            assert s is inst
        inst.shutdown.assert_called_once()


@pytest.mark.unit
def test_bridge_session_host_qnum_from_slot_name():
    from blockchecks.service.lua_session import BridgeSession

    s = BridgeSession(
        ns_name=f"host-q222-{os.getpid()}",
        strategies=["fake:blob=stun:repeats=6"],
        bridge=MagicMock(),
        host_qnum=222,
    )
    assert s.is_host and s.host_qnum == 222


@pytest.mark.unit
def test_bridge_session_netns_default():
    from blockchecks.service.lua_session import BridgeSession

    s = BridgeSession(
        ns_name="bs-p-0001-0",
        strategies=["fake:blob=stun:repeats=6"],
        bridge=MagicMock(),
    )
    assert not s.is_host and s.host_qnum == 0


@pytest.mark.unit
def test_bridge_session_host_boot_conf_and_teardown(tmp_path):
    """Host boot: conf carries qnum/fwmark/filter-mark; daemon killed by PID
    on shutdown; nft attached once after bind (canon §18.6)."""
    from blockchecks.service.lua_session import BridgeSession

    s = BridgeSession(
        ns_name=f"host-q220-{os.getpid()}",
        strategies=["fake:blob=stun:repeats=6"],
        bridge=MagicMock(),
        protocol="tls12",
        host_qnum=220,
    )
    captured = {}

    def fake_daemon_host(conf_path, *, qnum, **kw):
        captured["conf"] = Path(conf_path).read_text(encoding="utf-8")
        captured["qnum"] = qnum
        return 0.12, MagicMock(pid=777)

    with (
        patch(
            "blockchecks.service.nfqws2_launcher.daemon_host",
            side_effect=fake_daemon_host,
        ),
        patch(
            "blockchecks.service.host_isol.attach_host_queue"
        ) as attach,
        patch("blockchecks.service.nfqws2_launcher.kill_host_daemon") as kill,
        patch(
            "blockchecks.service.host_isol.detach_host_slot_rule",
            return_value=True,
        ) as detach,
        patch(
            "blockchecks.service.lua_conf.stage_blockchecks_lua",
            return_value=[],
        ),
        patch(
            "blockchecks.service.lua_conf.get_lua_init_scripts",
            return_value=[],
        ),
    ):
        settle = s.boot()
        assert settle == 0.12
        assert captured["qnum"] == 220
        conf = captured["conf"]
        assert "--qnum=220" in conf
        assert "--fwmark=0x40000000" in conf
        assert "--filter-mark=0x20000000/0x20000000" in conf
        assert "--writable=" in conf
        attach.assert_called_once()
        assert s.iptables_ready is True

        s.shutdown()
        kill.assert_called_once_with(220)
        detach.assert_called_once_with(220)
        assert s.iptables_ready is False
        assert s.conf_path == ""
