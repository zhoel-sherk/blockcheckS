from __future__ import annotations

from unittest.mock import patch

import pytest

from blockchecks.service.host_slots import HostSlotPool, slot_name


@pytest.mark.unit
def test_slot_names_canonical_shape():
    assert slot_name(220).startswith("host-q220-")
    assert slot_name(220) != "host"


@pytest.mark.unit
def test_pool_qnums_even_step_from_base():
    pool = HostSlotPool(size=3, base_qnum=220)
    assert pool._qnums() == [220, 222, 224]
    with (
        patch("blockchecks.service.probe.release_curl_probe_worker"),
        patch("blockchecks.service.host_isol.teardown_host_queue", return_value=False),
    ):
        pool.create_all()
        assert all(n.startswith("host-q") for n in pool._names)
        assert len(pool._names) == 3
        # idempotent
        pool.create_all()
        assert len(pool._names) == 3
        pool.destroy_all()  # clears atexit armed state — no real nft at exit


@pytest.mark.unit
def test_pool_validate_hard_refusals(monkeypatch):
    """validate() imports from host_isol at call time — patch there (canon:
    missing nft / busy qnum = hard refusal, never silent rotation §6/§18.1)."""
    from blockchecks.service import host_isol

    pool = HostSlotPool(size=1, base_qnum=220)
    monkeypatch.setattr(host_isol, "nft_available", lambda: False)
    with pytest.raises(RuntimeError, match="requires nft"):
        pool.validate()

    monkeypatch.setattr(host_isol, "nft_available", lambda: True)
    monkeypatch.setattr(host_isol, "qnum_busy", lambda q: "ip: foreign rule queue num 220")
    with pytest.raises(RuntimeError, match="already queued"):
        pool.validate()


@pytest.mark.unit
def test_pool_acquire_release_roundtrip():
    import asyncio

    pool = HostSlotPool(size=2, base_qnum=220)
    with (
        patch("blockchecks.service.probe.release_curl_probe_worker"),
        patch("blockchecks.service.host_isol.teardown_host_queue", return_value=False),
    ):
        pool.create_all()

        async def flow():
            await pool.seed()
            a = await pool.acquire()
            b = await pool.acquire()
            assert a != b
            await pool.release(a)
            c = await pool.acquire()
            assert c == a
            await pool.drain()

        asyncio.run(flow())
        pool.destroy_all()  # disarm atexit — no real nft/worker calls at exit


@pytest.mark.unit
def test_pool_destroy_all_releases_workers_and_table():
    calls = []

    def fake_release(name):
        calls.append(("worker", name))

    with (
        patch(
            "blockchecks.service.probe.release_curl_probe_worker",
            side_effect=fake_release,
        ),
        patch(
            "blockchecks.service.host_isol.teardown_host_queue",
            return_value=True,
        ) as th,
    ):
        pool = HostSlotPool(size=2, base_qnum=220)
        pool.create_all()
        pool.destroy_all()
    assert len(calls) == 2
    th.assert_called_once()
    assert pool._names == []
