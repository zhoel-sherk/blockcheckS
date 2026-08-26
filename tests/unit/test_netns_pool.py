"""Unit tests for NetNsPool create/destroy/acquire sequences (mocked sudo)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import blockchecks.service.netns_pool as nsp
from blockchecks.service.netns_pool import NetNsPool

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_ip_forward_state():
    nsp._ACTIVE_NS_COUNT = 0
    nsp._IP_FORWARD_RESTORE = None
    yield
    nsp._ACTIVE_NS_COUNT = 0
    nsp._IP_FORWARD_RESTORE = None

@pytest.mark.asyncio
async def test_create_seed_acquire_release_destroy():
    pool = NetNsPool(size=2, base="bs-t")
    cmds: list[list[str]] = []

    def fake_run(*args, check=True):
        cmds.append(list(args))
        return MagicMock(returncode=0, stdout="", stderr="")

    with (
        patch.object(pool, "_run", side_effect=fake_run),
        patch.object(pool, "_get_iface", return_value="eth0"),
        patch("blockchecks.service.netns_pool.subprocess.run") as sprun,
        patch("blockchecks.service.netns_pool.time.sleep"),
    ):
        sprun.return_value = MagicMock(returncode=0, stdout="", stderr="")
        pool.create_all()
        assert pool._created is True
        assert pool._names == ["bs-t-0", "bs-t-1"]
        assert any(c[:3] == ["ip", "netns", "add"] for c in cmds)

        await pool.seed()
        a = await pool.acquire()
        b = await pool.acquire()
        assert {a, b} == {"bs-t-0", "bs-t-1"}

        await pool.release(a)
        again = await pool.acquire()
        assert again == a

        await pool.drain()
        pool.destroy_all()
        assert pool._created is False
        assert pool._names == []
        assert any(c[:3] == ["ip", "netns", "delete"] for c in cmds)


def test_create_one_failure_propagates():
    pool = NetNsPool(size=1, base="bs-t")

    def boom(*args, check=True):
        if args[:3] == ("ip", "netns", "add"):
            raise RuntimeError("cmd failed: ip netns add")
        return MagicMock(returncode=0, stdout="", stderr="")

    with (
        patch.object(pool, "_run", side_effect=boom),
        patch.object(pool, "_get_iface", return_value="eth0"),
        patch("blockchecks.service.netns_pool.time.sleep"),
    ):
        with pytest.raises(RuntimeError, match="netns add"):
            pool.create_all()
    assert pool._created is False


def test_get_iface_skips_veth_and_peer():
    """_get_iface must not pick a leftover veth/peer as the out-interface."""
    from unittest.mock import MagicMock, patch

    pool = NetNsPool(size=1, base="bs-t")
    fake_output = (
        "lo               UNKNOWN        127.0.0.1/8\n"
        "vh-bs-p-1234-3@if513 UP             c2:89:35:34:b7:b7\n"
        "enp2s0           DOWN\n"
        "wlp4s0           UP             192.168.1.132/24\n"
    )
    with patch(
        "blockchecks.service.netns_pool.subprocess.run",
        return_value=MagicMock(returncode=0, stdout=fake_output, stderr=""),
    ):
        assert pool._get_iface() == "wlp4s0"


def test_run_uses_sudo_n():
    pool = NetNsPool(size=1, base="bs-t")
    with patch("blockchecks.service.netns_pool.subprocess.run") as sprun:
        sprun.return_value = MagicMock(returncode=0, stdout="", stderr="")
        pool._run("ip", "netns", "add", "bs-t-0")
    sprun.assert_called_once()
    assert sprun.call_args.args[0][:2] == ["sudo", "-n"]


def test_run_raises_on_passwordless_sudo_failure():
    pool = NetNsPool(size=1, base="bs-t")
    auth_fail = MagicMock(
        returncode=1,
        stdout="",
        stderr="sudo: a password is required",
    )
    with patch("blockchecks.service.netns_pool.subprocess.run", return_value=auth_fail):
        with pytest.raises(RuntimeError, match="passwordless sudo required"):
            pool._run("ip", "netns", "add", "bs-t-0")


def test_install_signal_hooks_logs_on_failure(caplog):
    import blockchecks.service.netns_pool as nsp

    nsp._SIGNAL_HOOKS_INSTALLED = False
    with (
        patch("blockchecks.service.netns_pool.signal.signal", side_effect=ValueError("not main")),
        caplog.at_level("WARNING"),
    ):
        NetNsPool.install_signal_hooks()
    assert any("signal hook install failed" in r.message for r in caplog.records)
    nsp._SIGNAL_HOOKS_INSTALLED = False


def test_create_all_rollback_logs_destroy_failure(caplog):
    pool = NetNsPool(size=2, base="bs-t")
    add_calls = 0

    def boom(*args, check=True):
        nonlocal add_calls
        if args[:3] == ("ip", "netns", "add"):
            add_calls += 1
            if add_calls == 2:
                raise RuntimeError("cmd failed: ip netns add")
        return MagicMock(returncode=0, stdout="", stderr="")

    with (
        patch.object(pool, "_run", side_effect=boom),
        patch.object(pool, "_get_iface", return_value="eth0"),
        patch.object(pool, "_destroy_one", side_effect=RuntimeError("destroy boom")),
        patch("blockchecks.service.netns_pool.subprocess.run") as sprun,
        patch("blockchecks.service.netns_pool.time.sleep"),
        caplog.at_level("WARNING"),
    ):
        sprun.return_value = MagicMock(returncode=0, stdout="", stderr="")
        with pytest.raises(RuntimeError, match="netns add"):
            pool.create_all()
    assert any("rollback destroy failed" in r.message for r in caplog.records)


def test_create_all_rollback_includes_name_before_create(caplog):
    """RT-2: partial create rolls back names registered before ip netns add."""
    pool = NetNsPool(size=1, base="bs-t")
    destroyed: list[str] = []

    def boom(*args, check=True):
        if args[:3] == ("ip", "netns", "add"):
            return MagicMock(returncode=0, stdout="", stderr="")
        if args[:3] == ("ip", "link", "add"):
            raise RuntimeError("veth add failed")
        return MagicMock(returncode=0, stdout="", stderr="")

    def capture_destroy(name, *, track_lifecycle=True):
        destroyed.append(name)
        return True

    with (
        patch.object(pool, "_run", side_effect=boom),
        patch.object(pool, "_get_iface", return_value="eth0"),
        patch.object(pool, "_destroy_one", side_effect=capture_destroy),
        patch("blockchecks.service.netns_pool.subprocess.run") as sprun,
        patch("blockchecks.service.netns_pool.time.sleep"),
        caplog.at_level("WARNING"),
    ):
        sprun.return_value = MagicMock(returncode=0, stdout="", stderr="")
        with pytest.raises(RuntimeError, match="veth add failed"):
            pool.create_all()
    assert destroyed == ["bs-t-0"]


def test_destroy_all_keeps_names_until_teardown_finishes():
    pool = NetNsPool(size=2, base="bs-t")
    pool._created = True
    pool._names = ["bs-t-0", "bs-t-1"]
    seen_during_destroy: list[list[str]] = []

    def capture_destroy(name, *, track_lifecycle=True):
        seen_during_destroy.append(list(pool._names))
        return True

    with patch.object(pool, "_destroy_one", side_effect=capture_destroy):
        pool.destroy_all()
    assert seen_during_destroy == [["bs-t-0", "bs-t-1"], ["bs-t-0", "bs-t-1"]]
    assert pool._names == []


def test_run_destroy_logs_nonzero_rc(caplog):
    pool = NetNsPool(size=1, base="bs-t")

    def fail_delete(*args, check=True):
        if args[:3] == ("ip", "netns", "delete"):
            return MagicMock(returncode=1, stdout="", stderr="delete failed")
        return MagicMock(returncode=0, stdout="", stderr="")

    with (
        patch.object(pool, "_run", side_effect=fail_delete),
        patch.object(pool, "_get_iface", return_value="eth0"),
        patch("blockchecks.service.metrics.pkill_nfqws2_in_ns"),
        caplog.at_level("WARNING"),
    ):
        pool._destroy_one("bs-t-0", track_lifecycle=False)
    assert any("netns destroy rc=1" in r.message for r in caplog.records)


def test_destroy_all_warns_on_leftovers(caplog):
    pool = NetNsPool(size=2, base="bs-t")
    pool._created = True
    pool._names = ["bs-t-0", "bs-t-1"]

    def mixed_destroy(name, *, track_lifecycle=True):
        return name == "bs-t-0"

    with (
        patch.object(pool, "_destroy_one", side_effect=mixed_destroy),
        caplog.at_level("WARNING"),
    ):
        pool.destroy_all()
    assert any("1/2 namespaces may remain" in r.message for r in caplog.records)


def test_ip_forward_saved_and_restored_on_last_destroy():
    pool = NetNsPool(size=1, base="bs-t")
    sysctl_cmds: list[tuple[str, ...]] = []

    def fake_run(*args, check=True):
        if args[:2] == ("sysctl", "-w"):
            sysctl_cmds.append(tuple(args))
        return MagicMock(returncode=0, stdout="", stderr="")

    with (
        patch.object(pool, "_run", side_effect=fake_run),
        patch.object(pool, "_get_iface", return_value="eth0"),
        patch.object(nsp, "_read_ip_forward", return_value="0"),
        patch.object(nsp, "_write_ip_forward_restore"),
        patch.object(nsp, "_clear_ip_forward_restore_marker"),
        patch("blockchecks.service.netns_pool.subprocess.run") as sprun,
        patch("blockchecks.service.netns_pool.time.sleep"),
        patch("blockchecks.service.metrics.pkill_nfqws2_in_ns"),
    ):
        sprun.return_value = MagicMock(returncode=0, stdout="", stderr="")
        pool.create_all()
        pool.destroy_all()
    assert ("sysctl", "-w", "net.ipv4.ip_forward=1") in sysctl_cmds
    assert ("sysctl", "-w", "net.ipv4.ip_forward=0") in sysctl_cmds


def test_destroy_one_releases_curl_worker():
    pool = NetNsPool(size=1, base="bs-t")
    with (
        patch.object(pool, "_run", return_value=MagicMock(returncode=0, stdout="", stderr="")),
        patch.object(pool, "_get_iface", return_value="eth0"),
        patch("blockchecks.service.metrics.pkill_nfqws2_in_ns"),
        patch("blockchecks.service.ns_firewall.drop_ns_firewall"),
        patch("blockchecks.service.probe.release_curl_probe_worker") as release,
    ):
        pool._destroy_one("bs-t-0", track_lifecycle=False)
    release.assert_called_once_with("bs-t-0")


def test_destroy_one_drops_ns_firewall():
    pool = NetNsPool(size=1, base="bs-t")

    with (
        patch.object(pool, "_run", return_value=MagicMock(returncode=0, stdout="", stderr="")),
        patch.object(pool, "_get_iface", return_value="eth0"),
        patch("blockchecks.service.metrics.pkill_nfqws2_in_ns"),
        patch("blockchecks.service.ns_firewall.drop_ns_firewall") as drop_fw,
    ):
        pool._destroy_one("bs-t-0", track_lifecycle=False)
    drop_fw.assert_called_once_with("bs-t-0")


def test_ip_forward_not_saved_when_already_enabled():
    pool = NetNsPool(size=1, base="bs-t")
    sysctl_cmds: list[tuple[str, ...]] = []

    def fake_run(*args, check=True):
        if args[:2] == ("sysctl", "-w"):
            sysctl_cmds.append(tuple(args))
        return MagicMock(returncode=0, stdout="", stderr="")

    with (
        patch.object(pool, "_run", side_effect=fake_run),
        patch.object(pool, "_get_iface", return_value="eth0"),
        patch.object(nsp, "_read_ip_forward", return_value="1"),
        patch("blockchecks.service.netns_pool.subprocess.run") as sprun,
        patch("blockchecks.service.netns_pool.time.sleep"),
        patch("blockchecks.service.metrics.pkill_nfqws2_in_ns"),
    ):
        sprun.return_value = MagicMock(returncode=0, stdout="", stderr="")
        pool.create_all()
        pool.destroy_all()
    assert sysctl_cmds == []
