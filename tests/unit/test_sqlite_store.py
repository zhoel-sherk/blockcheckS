"""SqliteRunStore DAO tests."""

from __future__ import annotations

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
        "s1", "discord.com", "FAIL", 100.0, 0,
        error="curl: (35) Recv failure: Connection reset",
        config_path="fake:blob=stun", fail_phase="tls_rst_at_sni",
    )
    await store.flush()
    con = sqlite3.connect(tmp_path / "fp.db")
    row = con.execute(
        "SELECT fail_phase FROM tcp_results WHERE domain='discord.com'"
    ).fetchone()
    assert row is not None
    assert row[0] == "tls_rst_at_sni"
    con.close()


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
    await store.flush()

    keys = await store.get_completed_tcp_keys()
    assert ("s1", "a.com") in keys
    assert ("s2", "b.com") in keys
    # quic proto excluded by default (tcp only)
    assert ("s3", "c.com") not in keys

    keys_q = await store.get_completed_tcp_keys(proto="quic")
    assert ("s3", "c.com") in keys_q


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
    _orig_connect = aiosqlite.connect

    def _connect(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return _RaiseLocked()
        return _orig_connect(*args, **kwargs)

    monkeypatch.setattr(aiosqlite, "connect", _connect)
    await store.flush()  # attempt 0 locked -> retry 1 commits
    assert not store._tcp_pending
    con = sqlite3.connect(tmp_path / "req.db")
    rows = con.execute("SELECT COUNT(*) FROM tcp_results").fetchone()[0]
    con.close()
    assert rows == 1


class _RaiseLocked:
    """aiosqlite.connect() replacement that raises OperationalError on enter."""

    def __init__(self):
        import aiosqlite

        self._exc = aiosqlite.OperationalError("database is locked")

    async def __aenter__(self):
        raise self._exc

    async def __aexit__(self, *exc):
        return False


@pytest.mark.unit
@pytest.mark.asyncio
async def test_flush_requeues_on_failure(tmp_path, monkeypatch):
    """Failed flush must re-queue rows so results are never lost."""
    import aiosqlite

    store = open_run_store(tmp_path / "req2.db", batch_size=10)
    await store.init()
    await store.log_tcp("s1", "a.com", "PASS", 10.0, 200, config_path="fake:1")

    def _always_locked(*args, **kwargs):
        return _RaiseLocked()

    monkeypatch.setattr(aiosqlite, "connect", _always_locked)
    with pytest.raises(aiosqlite.OperationalError):
        await store.flush()
    # Rows re-queued (nothing silently dropped).
    assert len(store._tcp_pending) == 1
