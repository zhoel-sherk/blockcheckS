"""Tests for wall timeout, googlevideo solo fan-out, family finish, and THROTTLED-as-working."""

from __future__ import annotations

import pytest

from blockchecks.checkers.curl_probe import worker_wall_timeout
from blockchecks.engine.adaptive_queue import AdaptiveJobQueue
from blockchecks.engine.family_needs import FamilyNeedTracker, classify_strategy_family
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.store import open_run_store

pytestmark = pytest.mark.unit


def test_worker_wall_timeout_scales_with_repeats():
    t = worker_wall_timeout(5.0, repeats=5, settle_slack=15.0)
    assert t >= 5.0 * 5 + 15.0
    # parallel_repeats collapses to one wave
    tp = worker_wall_timeout(5.0, repeats=5, parallel_repeats=True, settle_slack=15.0)
    assert tp >= 5.0 + 15.0
    assert tp < t


def test_pop_batch_solos_googlevideo():
    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    domains = [
        "rr1---sn-a.googlevideo.com",
        "rr2---sn-b.googlevideo.com",
        "discord.com",
    ]
    q = AdaptiveJobQueue.build([item], domains, epsilon=0.0, seed=1)
    batch = q.pop_batch(8, protocol="tls12")
    assert len(batch) == 1
    assert "googlevideo" in batch[0].domain


def test_finish_family_fakedsplit_clears_needs():
    assert classify_strategy_family(StrategyItem("std_fds_x", "fakedsplit:pos=1")) == "fakedsplit"
    tracker = FamilyNeedTracker()
    tracker.finish_family("fakedsplit", True)
    assert tracker.need_fakedsplit == 0
    assert tracker.need_fakeddisorder == 0
    dep = StrategyItem("std_ffds_x", "fake:blob=stun\nfakedsplit:pos=1")
    assert tracker.skip_strategy(dep, "fast") is True


@pytest.mark.asyncio
async def test_throttled_counts_as_working(tmp_path):
    db = open_run_store(tmp_path / "t.db")
    await db.init()
    await db.log_tcp("s1", "discord.com", "THROTTLED", 100.0, http_code=206)
    await db.log_tcp("s2", "discord.com", "PASS", 50.0, http_code=200)
    await db.log_tcp("s3", "discord.com", "FAIL", 0.0, http_code=0)
    working = await db.get_working_tcp("discord.com")
    assert "s1" in working
    assert "s2" in working
    assert "s3" not in working
    details = await db.get_working_tcp_details("discord.com")
    by_name = {d["name"]: d for d in details}
    assert by_name["s1"]["status"] == "THROTTLED"
    assert by_name["s2"]["status"] == "PASS"
    cov = await db.coverage_score("s1")
    assert cov["domains_passed"] == 1


@pytest.mark.asyncio
async def test_tcp_results_from_details_throttled():
    from blockchecks.engine.async_runner import tcp_results_from_details

    item = StrategyItem(label="s1", strategy="fake:repeats=1")
    results = tcp_results_from_details(
        {"s1": item},
        [{"name": "s1", "status": "THROTTLED", "latency_ms": 120.0}],
        "discord.com",
    )
    assert len(results) == 1
    assert results[0].success is True
    assert results[0].throttled is True
    assert results[0].latency_ms == 120.0


@pytest.mark.asyncio
async def test_get_best_pairs_includes_throttled(tmp_path):
    db = open_run_store(tmp_path / "pairs.db")
    await db.init()
    await db.log_pair(
        "tcp_a", "udp_a", "discord.com", True, True, True, 100.0, 0.0, 50.0, "THROTTLED"
    )
    await db.log_pair("tcp_b", "udp_b", "discord.com", True, True, True, 80.0, 0.0, 40.0, "PASS")
    await db.log_pair("tcp_c", "udp_c", "discord.com", False, False, False, 0.0, 0.0, 0.0, "FAIL")
    best = await db.get_best_pairs("discord.com", limit=10)
    overalls = {r["overall"] for r in best}
    assert "THROTTLED" in overalls
    assert "PASS" in overalls
    assert "FAIL" not in overalls


@pytest.mark.asyncio
async def test_flush_rollback_preserves_pending(tmp_path):
    """On flush failure rows must return to pending (ST-2 long-lived writer).

    Мок ставится ДО init(): writer-соединение кэшируется лениво, поздний
    перехват уже не действует. Проксируем настоящий aiosqlite.Connection,
    подменяя только executemany.
    """
    import blockchecks.engine.store.sqlite_store as mod

    db = open_run_store(tmp_path / "flush.db")
    orig_connect = mod.aiosqlite.connect
    injected = {"n": 0}

    class _BoomProxy:
        def __init__(self, conn):
            self._conn = conn

        async def __aenter__(self):
            await self._conn.__aenter__()
            return self

        async def __aexit__(self, *exc):
            return await self._conn.__aexit__(*exc)

        def __getattr__(self, name):
            return getattr(self._conn, name)

        async def executemany(self, sql, seq=()):
            if isinstance(sql, str) and "INSERT INTO tcp_results" in sql:
                injected["n"] += 1
                raise RuntimeError("inject fail")
            return await self._conn.executemany(sql, seq)

    class _ConnectAwaitable:
        def __init__(self, cm):
            self._cm = cm

        def __await__(self):
            async def _resolve():
                conn = await self._cm
                return _BoomProxy(conn)
            return _resolve().__await__()

    def boom_connect(*a, **k):
        return _ConnectAwaitable(orig_connect(*a, **k))

    mod.aiosqlite.connect = boom_connect  # type: ignore[assignment]
    try:
        await db.init()
        db.batch_size = 100
        await db.log_tcp("s1", "discord.com", "PASS", 10.0, http_code=200)
        assert len(db._tcp_pending) == 1
        # Контракт ST-2/RT: flush ретраит внутри, затем бросает; rollback
        # возвращает строки в pending.
        with pytest.raises(RuntimeError, match="inject fail"):
            await db.flush()
        assert injected["n"] >= 1
        assert len(db._tcp_pending) == 1, "rollback обязан сохранить pending"
    finally:
        mod.aiosqlite.connect = orig_connect
        try:
            await db.close()
        except Exception:
            pass



@pytest.mark.asyncio
async def test_completed_pair_keys(tmp_path):
    db = open_run_store(tmp_path / "p.db")
    await db.init()
    await db.log_pair("t1", "u1", "discord.com", True, False, True, 10, 0, 20, "PASS")
    await db.log_pair("t1", "u2", "discord.com", True, False, False, 10, 0, 0, "PARTIAL")
    keys = await db.get_completed_pair_keys("discord.com")
    assert ("t1", "u1") in keys
    assert ("t1", "u2") in keys


def test_netns_base_reject_shell_metachar():
    from blockchecks.service.netns_pool import NetNsPool

    with pytest.raises(ValueError):
        NetNsPool(size=1, base="bs;rm")
