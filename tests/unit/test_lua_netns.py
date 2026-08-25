"""Unit tests for lua_netns — netns/iptables helpers for the lua bridge."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from blockchecks.service.lua_netns import (
    IptablesError,
    NetnsGoneError,
    _bridge_iptables_add,
    _check_netns_exists,
    _netns_tcp_probe_cleanup,
)

pytestmark = pytest.mark.unit


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
    # pkill is now PID-scoped via metrics (netns-exec pkill is host-wide!);
    # only the iptables -F remains a subprocess call.
    with patch("subprocess.run") as run, patch(
        "blockchecks.service.metrics.pkill_nfqws2_in_ns", return_value=0
    ) as pk:
        _netns_tcp_probe_cleanup("bs-p-0")
    assert pk.call_count == 1 and pk.call_args.args == ("bs-p-0",)
    assert run.call_count == 1


def _ok_run(*_a, **_k):
    r = MagicMock()
    r.returncode = 0
    r.stdout = ""
    r.stderr = ""
    return r


def test_bridge_iptables_add_tcp():
    with patch("subprocess.run", side_effect=_ok_run) as run, patch(
        "blockchecks.service.lua_netns._check_netns_exists"
    ):
        _bridge_iptables_add("bs-p-0", "443", "tls12")
    assert run.call_count == 3  # flush + add + -C verify
    args = run.call_args_list[1].args[0]
    assert "-p" in args and "tcp" in args


def test_bridge_iptables_add_quic():
    with patch("subprocess.run", side_effect=_ok_run) as run, patch(
        "blockchecks.service.lua_netns._check_netns_exists"
    ):
        _bridge_iptables_add("bs-p-0", "443", "quic")
    args = run.call_args_list[1].args[0]
    assert "udp" in args


def test_bridge_iptables_add_raises_when_add_fails():
    flush = _ok_run()
    add = MagicMock(returncode=1, stdout="", stderr="iptables: No chain")
    with (
        patch("subprocess.run", side_effect=[flush, add]),
        patch("blockchecks.service.lua_netns._check_netns_exists"),
        pytest.raises(IptablesError, match="NFQUEUE"),
    ):
        _bridge_iptables_add("bs-p-0", "443", "tls12")
