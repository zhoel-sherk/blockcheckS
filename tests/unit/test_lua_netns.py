"""Unit tests for lua_netns — netns/iptables helpers for the lua bridge."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from blockchecks.engine.config import NFQUEUE_TCP, NFQUEUE_UDP
from blockchecks.service.lua_netns import (
    IptablesError,
    NetnsGoneError,
    _bridge_iptables_add,
    _check_netns_exists,
    _netns_tcp_probe_cleanup,
)
from blockchecks.service.ns_firewall import reset_registry_for_tests

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clear_registry():
    reset_registry_for_tests()
    yield
    reset_registry_for_tests()


def test_check_netns_exists_found():
    r = MagicMock()
    r.stdout = "bs-p-0\nbs-p-1\n"
    with patch("subprocess.run", return_value=r):
        _check_netns_exists("bs-p-1")  # must not raise


def test_check_netns_exists_prefix_match():
    r = MagicMock()
    r.stdout = "bs-p-1  (id: 5)\n"
    with patch("subprocess.run", return_value=r):
        _check_netns_exists("bs-p-1")


def test_check_netns_missing_raises():
    r = MagicMock()
    r.stdout = "bs-p-0\n"
    with patch("subprocess.run", return_value=r):
        with pytest.raises(NetnsGoneError):
            _check_netns_exists("bs-p-9")


def test_netns_tcp_probe_cleanup():
    with (
        patch("blockchecks.service.metrics.pkill_nfqws2_in_ns", return_value=0) as pk,
        patch("blockchecks.service.lua_netns.mark_ns_dirty") as md,
        patch("blockchecks.service.lua_netns.get_ns_firewall") as get_fw,
    ):
        fw = MagicMock()
        get_fw.return_value = fw
        _netns_tcp_probe_cleanup("bs-p-0")
    assert pk.call_args.args == ("bs-p-0",)
    md.assert_called_once_with("bs-p-0")
    fw.detach.assert_called_once()


def test_bridge_iptables_add_tcp():
    with (
        patch("blockchecks.service.lua_netns._check_netns_exists"),
        patch("blockchecks.service.lua_netns.get_ns_firewall") as get_fw,
    ):
        fw = MagicMock()
        get_fw.return_value = fw
        _bridge_iptables_add("bs-p-0", "443", "tls12")
    fw.attach.assert_called_once_with(proto="tcp", port="443", queue=NFQUEUE_TCP)


def test_bridge_iptables_add_quic():
    with (
        patch("blockchecks.service.lua_netns._check_netns_exists"),
        patch("blockchecks.service.lua_netns.get_ns_firewall") as get_fw,
    ):
        fw = MagicMock()
        get_fw.return_value = fw
        _bridge_iptables_add("bs-p-0", "443", "quic")
    fw.attach.assert_called_once_with(proto="udp", port="443", queue=NFQUEUE_UDP)


def test_bridge_iptables_add_raises_when_add_fails():
    with (
        patch("blockchecks.service.lua_netns._check_netns_exists"),
        patch("blockchecks.service.lua_netns.get_ns_firewall") as get_fw,
        pytest.raises(IptablesError, match="NFQUEUE"),
    ):
        fw = MagicMock()
        fw.attach.side_effect = IptablesError("bs-p-0: iptables -A NFQUEUE/200 failed")
        get_fw.return_value = fw
        _bridge_iptables_add("bs-p-0", "443", "tls12")


def test_iptables_verify_fail_raises():
    from blockchecks.service.ns_firewall import NsFirewall

    fw = NsFirewall("ns-x")

    def fake_run(*args, check=False):
        if args and args[0] == "-C":
            return MagicMock(returncode=1, stderr="iptables: Bad rule", stdout="")
        return MagicMock(returncode=0, stderr="", stdout="")

    with (
        patch.object(fw, "_run", side_effect=fake_run),
        patch("blockchecks.service.lua_netns.get_ns_firewall", return_value=fw),
        patch("blockchecks.service.lua_netns._check_netns_exists"),
        pytest.raises(IptablesError),
    ):
        _bridge_iptables_add("ns-x", "443")
