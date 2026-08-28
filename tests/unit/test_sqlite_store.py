"""SqliteRunStore DAO tests."""

from __future__ import annotations

import asyncio
import sqlite3

import pytest

from blockchecks.engine.store import open_run_store


@pytest.mark.unit
@pytest.mark.asyncio
async def test_count_tcp_passes_no_leak(tmp_path):
    store = open_run_store(tmp_path / "t.db")
    await store.init()
    await store.log_tcp("s1", "discord.com", "PASS", 100.0, 200, config_path="fake:blob=stun")
    await store.log_tcp("s2", "discord.com", "FAIL", 100.0, 0, config_path="fake:blob=x")
    assert await store.count_tcp_passes() == 1
    assert await store.count_tcp_passes("discord.com") == 1
    assert store.path == (tmp_path / "t.db").resolve()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_open_run_store_explicit_path(tmp_path):
    store = open_run_store(tmp_path / "custom.db")
    await store.init()
    assert store.path == (tmp_path / "custom.db").resolve()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_log_tcp_persists_fail_phase(tmp_path):
    import sqlite3

    store = open_run_store(tmp_path / "fp.db")
    await store.init()
    await store.log_tcp(
        "s1",
        "discord.com",
        "FAIL",
        100.0,
        0,
        error="curl: (35) Recv failure: Connection reset",
        config_path="fake:blob=stun",
        fail_phase="tls_rst_at_sni",
    )
    await store.flush()
    con = sqlite3.connect(tmp_path / "fp.db")
    row = con.execute("SELECT fail_phase FROM tcp_results WHERE domain='discord.com'").fetchone()
    assert row is not None
    assert row[0] == "tls_rst_at_sni"
    con.close()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_log_tcp_and_get_best_tcp_probe_host(tmp_path):
    store = open_run_store(tmp_path / "ph.db")
    await store.init()
    await store.log_tcp(
        "s1",
        "googlevideo.com",
        "PASS",
        80.0,
        200,
        config_path="fake:blob=stun",
        probe_host="rr4---sn-xjvho9k.googlevideo.com",
    )
    rows = await store.get_best_tcp("googlevideo.com", limit=5)
    assert rows[0]["probe_host"] == "rr4---sn-xjvho9k.googlevideo.com"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_best_tcp_excludes_pass_without_applied(tmp_path):
    store = open_run_store(tmp_path / "applied.db")
    await store.init()
    await store.log_tcp(
        "lua_false",
        "discord.com",
        "PASS",
        50.0,
        200,
        config_path="fake:blob=stun",
        bridge_applied=False,
    )
    await store.log_tcp(
        "lua_ok",
        "discord.com",
        "PASS",
        90.0,
        200,
        config_path="fake:blob=max_ru",
        bridge_applied=True,
    )
    await store.log_tcp(
        "oneshot",
        "discord.com",
        "PASS",
        80.0,
        200,
        config_path="fake:blob=google",
        bridge_applied=None,
    )
    names = {r["strategy"] for r in await store.get_best_tcp("discord.com", limit=10)}
    assert names == {"lua_ok", "oneshot"}
    working = await store.get_working_tcp("discord.com")
    assert "lua_false" not in working
    assert await store.count_tcp_passes("discord.com") == 2


@pytest.mark.unit
@pytest.mark.asyncio
async def test_migration_adds_fail_phase_column(tmp_path):
    import sqlite3

    # create a DB WITHOUT the fail_phase column (old schema)
    con = sqlite3.connect(tmp_path / "old.db")
    con.execute(
        """CREATE TABLE tcp_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            strategy_id INTEGER, domain TEXT, status TEXT,
            http_code INTEGER, latency_ms REAL, gateway_ws_ms REAL,
            content_valid INTEGER, read_rate_bps REAL, error TEXT,
            timestamp TEXT)"""
    )
    con.commit()
    con.close()

    store = open_run_store(tmp_path / "old.db")
    await store.init()  # apply_schema should ALTER-add fail_phase

    con = sqlite3.connect(tmp_path / "old.db")
    cols = [r[1] for r in con.execute("PRAGMA table_info(tcp_results)")]
    assert "fail_phase" in cols
    con.close()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_migration_adds_probe_host_column(tmp_path):
    import sqlite3

    con = sqlite3.connect(tmp_path / "old_ph.db")
    con.execute(
        """CREATE TABLE tcp_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            strategy_id INTEGER, domain TEXT, status TEXT,
            http_code INTEGER, latency_ms REAL, gateway_ws_ms REAL,
            content_valid INTEGER, read_rate_bps REAL, error TEXT,
            timestamp TEXT, fail_phase TEXT)"""
    )
    con.commit()
    con.close()

    store = open_run_store(tmp_path / "old_ph.db")
    await store.init()

    con = sqlite3.connect(tmp_path / "old_ph.db")
    cols = [r[1] for r in con.execute("PRAGMA table_info(tcp_results)")]
    assert "probe_host" in cols
    con.close()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_dao_get_working_quic_proto_details(tmp_path):
    store = open_run_store(tmp_path / "w.db")
    await store.init()
    await store.log_tcp("q1", "x.com", "PASS", 50.0, 200, config_path="fake:quic", proto="quic")
    await store.log_tcp("q2", "x.com", "FAIL", 50.0, 0, config_path="fake:quic2", proto="quic")
    await store.flush()

    quic = await store.get_working_quic("x.com")
    assert "q1" in quic and "q2" not in quic

    proto = await store.get_working_proto("x.com", "quic")
    assert proto == ["q1"]

    details = await store.get_working_proto_details("x.com", "quic")
    assert details and details[0]["name"] == "q1"
    assert details[0]["status"] == "PASS"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_dao_get_completed_tcp_keys(tmp_path):
    store = open_run_store(tmp_path / "c.db")
    await store.init()
    await store.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")
    await store.log_tcp("s2", "b.com", "FAIL", 10.0, 0, config_path="fake:2")
    await store.log_tcp("s3", "c.com", "PASS", 10.0, 200, config_path="fake:3", proto="quic")
    await store.log_tcp("s4", "d.com", "THROTTLED", 10.0, 206, config_path="fake:4")
    await store.log_tcp("s5", "e.com", "SKIPPED", 0.0, 0, config_path="fake:5")
    await store.flush()

    keys = await store.get_completed_tcp_keys()
    assert ("s1", "a.com") in keys
    assert ("s4", "d.com") in keys
    assert ("s2", "b.com") not in keys
    assert ("s5", "e.com") not in keys
    # quic proto excluded by default (tcp only)
    assert ("s3", "c.com") not in keys

    keys_q = await store.get_completed_tcp_keys(proto="quic")
    assert ("s3", "c.com") in keys_q


@pytest.mark.unit
@pytest.mark.asyncio
async def test_dao_get_completed_tcp_keys_latest_row_only(tmp_path):
    store = open_run_store(tmp_path / "latest.db")
    await store.init()
    await store.log_tcp("s1", "retry.com", "FAIL", 10.0, 0, config_path="fake:1")
    await store.log_tcp("s1", "retry.com", "PASS", 20.0, 200, config_path="fake:1")
    await store.log_tcp("s2", "stale.com", "PASS", 10.0, 200, config_path="fake:2")
    await store.log_tcp("s2", "stale.com", "FAIL", 20.0, 0, config_path="fake:2")
    await store.flush()

    keys = await store.get_completed_tcp_keys()
    assert ("s1", "retry.com") in keys
    assert ("s2", "stale.com") not in keys


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_resume_skip_tcp_keys_working_skipped(tmp_path):
    store = open_run_store(tmp_path / "resume_skip.db")
    await store.init()
    await store.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")
    await store.log_tcp("s2", "b.com", "THROTTLED", 10.0, 206, config_path="fake:2")
    await store.flush()

    keys = await store.get_resume_skip_tcp_keys(reprobe_failed=2)
    assert ("s1", "a.com") in keys
    assert ("s2", "b.com") in keys


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_resume_skip_tcp_keys_infra_fail_requeued(tmp_path):
    store = open_run_store(tmp_path / "infra_reprobe.db")
    await store.init()
    await store.log_tcp(
        "s1",
        "infra.com",
        "FAIL",
        0.0,
        0,
        config_path="fake:1",
        fail_phase="connect_timeout",
    )
    await store.flush()

    keys_n0 = await store.get_resume_skip_tcp_keys(reprobe_failed=0)
    assert ("s1", "infra.com") not in keys_n0

    keys_n2 = await store.get_resume_skip_tcp_keys(reprobe_failed=2)
    assert ("s1", "infra.com") not in keys_n2


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_resume_skip_tcp_keys_dpi_fail_skipped_when_n_gt_zero(tmp_path):
    store = open_run_store(tmp_path / "dpi_skip.db")
    await store.init()
    await store.log_tcp(
        "s1",
        "dpi.com",
        "FAIL",
        0.0,
        0,
        config_path="fake:1",
        fail_phase="tls_silent_drop_after_sni",
    )
    await store.flush()

    keys_n0 = await store.get_resume_skip_tcp_keys(reprobe_failed=0)
    assert ("s1", "dpi.com") not in keys_n0

    keys_n2 = await store.get_resume_skip_tcp_keys(reprobe_failed=2)
    assert ("s1", "dpi.com") in keys_n2


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_resume_skip_tcp_keys_infra_exhausted_skipped(tmp_path):
    store = open_run_store(tmp_path / "infra_exhaust.db")
    await store.init()
    await store.log_tcp(
        "s1",
        "infra.com",
        "FAIL",
        0.0,
        0,
        config_path="fake:1",
        fail_phase="connect_timeout",
    )
    await store.log_tcp(
        "s1",
        "infra.com",
        "FAIL",
        0.0,
        0,
        config_path="fake:1",
        fail_phase="connect_timeout",
    )
    await store.flush()

    keys = await store.get_resume_skip_tcp_keys(reprobe_failed=2)
    assert ("s1", "infra.com") in keys


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_resume_skip_tcp_keys_infra_error_fallback(tmp_path):
    store = open_run_store(tmp_path / "infra_err.db")
    await store.init()
    await store.log_tcp(
        "s1",
        "shm.com",
        "FAIL",
        0.0,
        0,
        config_path="fake:1",
        fail_phase="other",
        error="ipc write failed: /dev/shm/blockchecks/bs-p-0/strategy.id",
    )
    await store.flush()

    keys = await store.get_resume_skip_tcp_keys(reprobe_failed=2)
    assert ("s1", "shm.com") not in keys


@pytest.mark.unit
@pytest.mark.asyncio
async def test_flush_concurrent_append_not_lost(tmp_path, monkeypatch):
    """A row appended AFTER flush snapshots its batch must never be cleared."""
    store = open_run_store(tmp_path / "race.db", batch_size=10)
    await store.init()
    await store.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")

    # Barrier: the first ensure_strategy call inside flush runs *after* the
    # snapshot is taken (s1 drained) — a concurrent writer appends s2 then.
    injected = {"done": False}
    orig_ensure = store.ensure_strategy

    async def _ensure(*args, **kwargs):
        if not injected["done"]:
            injected["done"] = True
            await store.log_tcp("s2", "b.com", "PASS", 20.0, 200, config_path="fake:2")
        return await orig_ensure(*args, **kwargs)

    monkeypatch.setattr(store, "ensure_strategy", _ensure)
    await store.flush()
    # s1 committed; s2 appended after the snapshot survives in the buffer.
    assert len(store._tcp_pending) == 1
    assert store._tcp_pending[0]["strategy"] == "s2"

    await store.flush()
    con = sqlite3.connect(tmp_path / "race.db")
    rows = con.execute(
        "SELECT s.name FROM tcp_results r JOIN strategies s ON s.id=r.strategy_id"
    ).fetchall()
    con.close()
    assert {r[0] for r in rows} == {"s1", "s2"}


@pytest.mark.unit
@pytest.mark.asyncio
async def test_flush_retry_recovers_and_clears(tmp_path, monkeypatch):
    """A locked flush retries, commits on success, and clears last_err."""
    import aiosqlite

    store = open_run_store(tmp_path / "req.db", batch_size=10)
    await store.init()
    await store.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")

    calls = {"n": 0}
    db = await store._writer()
    orig_execute = db.execute

    async def _execute(sql, *args, **kwargs):
        if "BEGIN IMMEDIATE" in str(sql) and calls["n"] == 0:
            calls["n"] += 1
            raise aiosqlite.OperationalError("database is locked")
        return await orig_execute(sql, *args, **kwargs)

    monkeypatch.setattr(db, "execute", _execute)
    await store.flush()
    assert not store._tcp_pending
    con = sqlite3.connect(tmp_path / "req.db")
    rows = con.execute("SELECT COUNT(*) FROM tcp_results").fetchone()[0]
    con.close()
    assert rows == 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_flush_requeues_on_failure(tmp_path, monkeypatch):
    """Failed flush must re-queue rows so results are never lost."""
    import aiosqlite

    store = open_run_store(tmp_path / "req2.db", batch_size=10)
    await store.init()
    await store.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")

    db = await store._writer()
    orig_execute = db.execute

    async def _always_locked(sql, *args, **kwargs):
        if "BEGIN IMMEDIATE" in str(sql):
            raise aiosqlite.OperationalError("database is locked")
        return await orig_execute(sql, *args, **kwargs)

    monkeypatch.setattr(db, "execute", _always_locked)
    with pytest.raises(aiosqlite.OperationalError):
        await store.flush()
    assert len(store._tcp_pending) == 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_writer_reuses_single_connection(tmp_path, monkeypatch):
    import aiosqlite

    calls = {"n": 0}
    orig_connect = aiosqlite.connect

    async def _counting_connect(*args, **kwargs):
        calls["n"] += 1
        return await orig_connect(*args, **kwargs)

    monkeypatch.setattr(aiosqlite, "connect", _counting_connect)
    store = open_run_store(tmp_path / "conn.db")
    await store.init()
    await store.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")
    await store.log_tcp("s2", "b.com", "PASS", 20.0, 200, config_path="fake:2")
    assert calls["n"] == 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_epoch_ms_set_at_log_time(tmp_path, monkeypatch):
    from itertools import count

    clock = count(1_700_000_000_000)
    store = open_run_store(tmp_path / "epoch.db")
    await store.init()

    monkeypatch.setattr(
        "blockchecks.engine.store.sqlite_store.time.time",
        lambda: next(clock) / 1000,
    )
    await store.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")
    await store.log_tcp("s2", "b.com", "PASS", 20.0, 200, config_path="fake:2")

    con = sqlite3.connect(tmp_path / "epoch.db")
    rows = con.execute("SELECT domain, epoch_ms FROM tcp_results ORDER BY id").fetchall()
    con.close()
    assert rows[0][0] == "a.com"
    assert rows[1][0] == "b.com"
    assert rows[0][1] < rows[1][1]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_settle_ms_zero_persisted(tmp_path):
    store = open_run_store(tmp_path / "settle.db")
    await store.init()
    await store.log_tcp(
        "s1",
        "a.com",
        "PASS",
        10.0,
        200,
        config_path="fake:1",
        settle_ms=0.0,
    )
    con = sqlite3.connect(tmp_path / "settle.db")
    row = con.execute("SELECT settle_ms FROM tcp_results").fetchone()
    con.close()
    assert row is not None
    assert row[0] == 0.0


@pytest.mark.unit
@pytest.mark.asyncio
async def test_flush_wal_checkpoint(tmp_path, monkeypatch):
    from blockchecks.engine.store import sqlite_store as mod

    store = open_run_store(tmp_path / "wal.db", batch_size=10)
    await store.init()
    monkeypatch.setattr(mod, "_WAL_CHECKPOINT_EVERY", 1)
    calls: list[str] = []
    db = await store._writer()
    orig_execute = db.execute

    async def _track_execute(sql, *args, **kwargs):
        calls.append(str(sql))
        return await orig_execute(sql, *args, **kwargs)

    monkeypatch.setattr(db, "execute", _track_execute)
    await store.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")
    await store.flush()
    assert any("wal_checkpoint(PASSIVE)" in c for c in calls)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_migration_adds_epoch_settle_content_columns(tmp_path):
    con = sqlite3.connect(tmp_path / "legacy.db")
    con.execute(
        """CREATE TABLE tcp_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            strategy_id INTEGER, domain TEXT, status TEXT,
            http_code INTEGER, latency_ms REAL, gateway_ws_ms REAL,
            content_valid INTEGER, read_rate_bps REAL, error TEXT,
            timestamp TEXT)"""
    )
    con.commit()
    con.close()

    store = open_run_store(tmp_path / "legacy.db")
    await store.init()

    con = sqlite3.connect(tmp_path / "legacy.db")
    cols = {r[1] for r in con.execute("PRAGMA table_info(tcp_results)").fetchall()}
    con.close()
    assert {"epoch_ms", "settle_ms", "content_len"}.issubset(cols)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_working_tcp_flushes_pending_batch(tmp_path):
    store = open_run_store(tmp_path / "batch.db", batch_size=500)
    await store.init()
    await store.log_tcp("s1", "discord.com", "PASS", 42.0, 200, config_path="fake:blob=stun")
    assert len(store._tcp_pending) == 1
    details = await store.get_working_tcp_details("discord.com")
    assert [d["name"] for d in details] == ["s1"]
    assert store._tcp_pending == []


@pytest.mark.unit
@pytest.mark.asyncio
async def test_save_triage_snapshot(tmp_path):
    store = open_run_store(tmp_path / "triage.db")
    await store.init()
    await store.save_triage_snapshot("youtube.com", {"silent_drop_after_sni": True})
    con = sqlite3.connect(tmp_path / "triage.db")
    row = con.execute("SELECT domain, payload_json FROM triage_snapshots").fetchone()
    con.close()
    assert row[0] == "youtube.com"
    assert "silent_drop" in row[1]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_migration_adds_idx_tcp_domain(tmp_path):
    store = open_run_store(tmp_path / "idx.db")
    await store.init()
    con = sqlite3.connect(tmp_path / "idx.db")
    names = {
        r[1]
        for r in con.execute("PRAGMA index_list(tcp_results)").fetchall()
    }
    con.close()
    assert "idx_tcp_domain" in names


@pytest.mark.unit
@pytest.mark.asyncio
async def test_batch_flush_per_row_timestamps(tmp_path, monkeypatch):
    stamps = ["2026-08-26T10:00:01", "2026-08-26T10:00:02"]
    store = open_run_store(tmp_path / "ts.db", batch_size=500)
    await store.init()

    def _stamp():
        return stamps.pop(0)

    monkeypatch.setattr(store, "_row_timestamp", _stamp)
    await store.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")
    await store.log_tcp("s2", "b.com", "PASS", 20.0, 200, config_path="fake:2")
    await store.flush()

    con = sqlite3.connect(tmp_path / "ts.db")
    rows = con.execute(
        "SELECT domain, timestamp FROM tcp_results ORDER BY id"
    ).fetchall()
    con.close()
    assert rows == [("a.com", "2026-08-26T10:00:01"), ("b.com", "2026-08-26T10:00:02")]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_timer_flush_drains_pending(tmp_path, monkeypatch):
    store = open_run_store(tmp_path / "timer.db", batch_size=500, flush_interval_sec=10)
    store._flush_interval = 0.05
    await store.init()
    await store.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")
    assert store._tcp_pending

    await asyncio.sleep(0.12)
    assert not store._tcp_pending

    con = sqlite3.connect(tmp_path / "timer.db")
    count = con.execute("SELECT COUNT(*) FROM tcp_results").fetchone()[0]
    con.close()
    assert count == 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_migration_adds_run_id_column(tmp_path):
    con = sqlite3.connect(tmp_path / "old_run.db")
    con.execute(
        """CREATE TABLE tcp_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            strategy_id INTEGER, domain TEXT, status TEXT,
            http_code INTEGER, latency_ms REAL, gateway_ws_ms REAL,
            content_valid INTEGER, read_rate_bps REAL, error TEXT,
            timestamp TEXT)"""
    )
    con.commit()
    con.close()

    store = open_run_store(tmp_path / "old_run.db")
    await store.init()

    con = sqlite3.connect(tmp_path / "old_run.db")
    cols = [r[1] for r in con.execute("PRAGMA table_info(tcp_results)")]
    assert "run_id" in cols
    tables = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    assert "runs" in tables
    con.close()

    await store.begin_run(fingerprint="fp1")
    await store.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")
    await store.flush()

    con = sqlite3.connect(tmp_path / "old_run.db")
    row = con.execute("SELECT run_id FROM tcp_results").fetchone()
    assert row is not None
    assert row[0] is not None
    con.close()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_run_id_isolates_completed_keys_between_campaigns(tmp_path):
    db_path = tmp_path / "iso.db"
    fp1 = "aaaaaaaaaaaaaaaa"
    fp2 = "bbbbbbbbbbbbbbbb"

    store1 = open_run_store(db_path)
    await store1.init()
    await store1.begin_run(fingerprint=fp1)
    await store1.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")
    await store1.flush()
    await store1.close()

    store2 = open_run_store(db_path, resume=False)
    await store2.init()
    await store2.begin_run(fingerprint=fp2)
    keys = await store2.get_completed_tcp_keys()
    assert ("s1", "a.com") not in keys
    assert keys == set()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_resume_reuses_run_id_and_completed_keys(tmp_path):
    db_path = tmp_path / "resume.db"
    fp = "cccccccccccccccc"

    store1 = open_run_store(db_path, resume=False)
    await store1.init()
    run1 = await store1.begin_run(fingerprint=fp)
    await store1.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")
    await store1.flush()
    await store1.close()

    store2 = open_run_store(db_path, resume=True)
    await store2.init()
    run2 = await store2.begin_run(fingerprint=fp)
    assert run2 == run1
    keys = await store2.get_completed_tcp_keys()
    assert ("s1", "a.com") in keys


@pytest.mark.unit
@pytest.mark.asyncio
async def test_flush_strategy_cache_one_ensure_per_strategy(tmp_path, monkeypatch):
    store = open_run_store(tmp_path / "cache.db", batch_size=500)
    await store.init()
    calls = {"n": 0}
    orig = store.ensure_strategy

    async def _counting(*args, **kwargs):
        calls["n"] += 1
        return await orig(*args, **kwargs)

    monkeypatch.setattr(store, "ensure_strategy", _counting)
    for i in range(5):
        await store.log_tcp(f"s{i}", "a.com", "PASS", 10.0, 200, config_path=f"fake:{i}")
    await store.flush()
    assert calls["n"] == 5

    for i in range(5):
        await store.log_tcp("same", f"d{i}.com", "PASS", 10.0, 200, config_path="fake:same")
    await store.flush()
    assert calls["n"] == 6


@pytest.mark.unit
@pytest.mark.asyncio
async def test_strategies_unique_name_proto_constraint(tmp_path):
    import aiosqlite

    store = open_run_store(tmp_path / "uniq.db")
    await store.init()
    async with aiosqlite.connect(store.db_path) as db:
        cur = await db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='strategies'"
        )
        ddl = (await cur.fetchone())[0]
        indexes = await db.execute("PRAGMA index_list(strategies)")
        unique = [row[1] for row in await indexes.fetchall() if row[2]]
    assert "UNIQUE(name,proto)" in "".join(ddl.split())
    assert unique
    await store.close()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_ensure_strategy_upsert_updates_nonempty_path(tmp_path):
    store = open_run_store(tmp_path / "up.db")
    await store.init()
    id1 = await store.ensure_strategy("fake_x", "tcp", "path_a")
    id2 = await store.ensure_strategy("fake_x", "tcp", "path_b")
    assert id1 == id2
    assert await store.get_strategy_config("fake_x", "tcp") == "path_b"
    id3 = await store.ensure_strategy("fake_x", "tcp", "")
    assert id3 == id1
    assert await store.get_strategy_config("fake_x", "tcp") == "path_b"
    await store.close()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_ensure_strategy_concurrent_two_connections(tmp_path):
    path = tmp_path / "race.db"
    a = open_run_store(path)
    b = open_run_store(path)
    await a.init()
    await b.init()
    ids = await asyncio.gather(
        a.ensure_strategy("shared", "tcp", "p1"),
        b.ensure_strategy("shared", "tcp", "p2"),
    )
    assert ids[0] == ids[1]
    cfg = await a.get_strategy_config("shared", "tcp")
    assert cfg in {"p1", "p2"}
    await a.close()
    await b.close()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_reclaim_skipped_on_hot_write_paths(tmp_path, monkeypatch):
    calls: list = []

    def _track(path):
        calls.append(str(path))

    monkeypatch.setattr(
        "blockchecks.engine.store.sqlite_store.reclaim_sudo_ownership", _track
    )
    store = open_run_store(tmp_path / "rc.db")
    await store.init()
    after_init = len(calls)
    await store.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")
    await store.log_udp("u1", "voice", "PASS", 5.0, config_path="fake:u")
    await store.quarantine_domain("dead.com", reason="zero")
    await store.save_triage_snapshot("a.com", {"ok": True})
    store.batch_size = 10
    await store.log_tcp("s2", "b.com", "PASS", 10.0, 200, config_path="fake:2")
    await store.flush()
    assert len(calls) == after_init
    await store.close()
    assert len(calls) == after_init + 1
