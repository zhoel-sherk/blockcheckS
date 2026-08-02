"""StateDB unit tests."""

from __future__ import annotations

import aiosqlite
import pytest

from blockchecks.engine.store import Checkpoint, SqliteRunStore

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_unique_name_proto(temp_db: SqliteRunStore):
    id1 = await temp_db.ensure_strategy("fake_r6", "tcp", "tcp_path")
    id2 = await temp_db.ensure_strategy("fake_r6", "udp", "udp_path")
    assert id1 != id2


@pytest.mark.asyncio
async def test_same_name_proto_idempotent(temp_db: SqliteRunStore):
    id1 = await temp_db.ensure_strategy("fake_x", "tcp", "path_a")
    id2 = await temp_db.ensure_strategy("fake_x", "tcp", "path_b")
    assert id1 == id2


@pytest.mark.asyncio
async def test_checkpoint_latest(temp_db: SqliteRunStore):
    await temp_db.save_checkpoint(0, 0, "first")
    await temp_db.save_checkpoint(2, 2, "third", fingerprint="fp", tcp_label="t", udp_label="u")
    cp = await temp_db.latest_checkpoint()
    assert isinstance(cp, Checkpoint)
    assert cp.tcp_idx == 2 and cp.udp_idx == 2
    assert cp.tcp_label == "t"


@pytest.mark.asyncio
async def test_views_exist(temp_db: SqliteRunStore):
    async with aiosqlite.connect(temp_db.db_path) as conn:
        r = await conn.execute("SELECT name FROM sqlite_master WHERE type='view'")
        views = [row[0] for row in await r.fetchall()]
    for v in ("v_working_tcp", "v_coverage", "v_latest_run"):
        assert v in views


@pytest.mark.asyncio
async def test_log_tcp_working(temp_db: SqliteRunStore):
    await temp_db.log_tcp("my_strat", "discord.com", "PASS", 115, 200)
    working = await temp_db.get_working_tcp("discord.com")
    assert "my_strat" in working
