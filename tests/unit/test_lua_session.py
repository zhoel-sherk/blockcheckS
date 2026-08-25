"""Unit tests for blockchecks.service.lua_session (mocked nfqws2/iptables)."""

from __future__ import annotations

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
    with (
        patch("subprocess.run") as m_run,
        patch("blockchecks.service.lua_session.os.unlink"),
    ):
        session.shutdown()
    assert session.iptables_ready is False
    assert m_run.call_count == 1  # iptables -F; pkill is PID-scoped now
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
def test_teardown_all_bridge_shm(tmp_path):
    shm = tmp_path / "blockchecks"
    shm.mkdir(parents=True)
    (shm / "x").write_text("", encoding="utf-8")
    teardown_all_bridge_shm(shm)
    assert not shm.exists()


@pytest.mark.unit
def test_teardown_all_bridge_shm_missing(tmp_path):
    teardown_all_bridge_shm(tmp_path / "nope")
    assert True


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
