"""Unit tests for NetNsPool create/destroy/acquire sequences (mocked sudo)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from blockchecks.service.netns_pool import NetNsPool

pytestmark = pytest.mark.unit


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
