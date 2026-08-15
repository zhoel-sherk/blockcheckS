"""SqliteRunStore DAO tests."""

from __future__ import annotations

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
