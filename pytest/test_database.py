"""Tests for StateDB — SQLite identity, checkpoint, views."""
import os, sys, pytest, tempfile, asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.db_logger import StateDB


@pytest.fixture
def db():
    """Fresh SQLite for each DB test."""
    path = tempfile.mktemp(suffix=".db")
    sdb = StateDB(path)
    asyncio.run(sdb.init())
    yield sdb
    try:
        os.unlink(path)
    except OSError:
        pass


class TestStrategyIdentity:
    def test_unique_name_proto(self, db):
        """TCP and UDP with same name get different IDs."""
        async def t():
            id1 = await db.ensure_strategy("fake_r6", "tcp", "tcp_path")
            id2 = await db.ensure_strategy("fake_r6", "udp", "udp_path")
            assert id1 != id2, f"Different proto should give different IDs: {id1} == {id2}"
        asyncio.run(t())

    def test_same_name_proto_is_idempotent(self, db):
        """Calling ensure_strategy twice with same name+proto returns same ID."""
        async def t():
            id1 = await db.ensure_strategy("fake_x", "tcp", "path_a")
            id2 = await db.ensure_strategy("fake_x", "tcp", "path_b")
            assert id1 == id2, f"Same (name,proto) should return same ID: {id1} != {id2}"
        asyncio.run(t())


class TestCheckpoint:
    def test_save_and_load(self, db):
        """Checkpoint is saved and can be loaded."""
        async def t():
            await db.save_checkpoint(0, 0, "test", fingerprint="fp1",
                                     tcp_label="tcp_a", udp_label="udp_a")
            cp = await db.latest_checkpoint()
            assert cp is not None
            assert cp[0] == 0 and cp[1] == 0
        asyncio.run(t())

    def test_latest_is_last(self, db):
        """latest_checkpoint returns the most recently saved one."""
        async def t():
            await db.save_checkpoint(0, 0, "first")
            await db.save_checkpoint(1, 1, "second")
            await db.save_checkpoint(2, 2, "third")
            cp = await db.latest_checkpoint()
            assert cp[0] == 2 and cp[1] == 2
        asyncio.run(t())


class TestViews:
    def test_views_exist(self, db):
        """SQL views are created in init()."""
        async def t():
            with db._get_conn() if hasattr(db, '_get_conn') else open(db.db_path):
                pass
            # Open connection and list views
            import aiosqlite
            async with aiosqlite.connect(db.db_path) as conn:
                r = await conn.execute("SELECT name FROM sqlite_master WHERE type='view'")
                views = [row[0] async for row in r]
                expected = ['v_working_tcp', 'v_coverage', 'v_latest_run']
                for v in expected:
                    assert v in views, f"View {v} missing from {views}"
        asyncio.run(t())

    def test_v_working_tcp_works(self, db):
        """v_working_tcp returns PASS strategies."""
        async def t():
            await db.log_tcp("strat_a", "discord.com", "PASS", 100, 200)
            await db.log_udp("strat_b", "1.2.3.4:5", "FAIL", 0, "timeout")
            import aiosqlite
            async with aiosqlite.connect(db.db_path) as conn:
                r = await conn.execute("SELECT strategy, domain FROM v_working_tcp")
                rows = [row async for row in r]
                assert len(rows) >= 1
                assert rows[0] == ("strat_a", "discord.com")
        asyncio.run(t())


class TestResultsLogging:
    def test_log_tcp_and_link(self, db):
        """log_tcp creates strategy + result properly."""
        async def t():
            await db.log_tcp("my_strat", "discord.com", "PASS", 115, 200)
            await db.log_tcp("my_strat", "youtube.com", "FAIL", 5000, 0, error="timeout")
            working = await db.get_working_tcp("discord.com")
            assert "my_strat" in working
        asyncio.run(t())

    def test_get_working_tcp_dedup(self, db):
        """get_working_tcp returns distinct strategies (no duplicates)."""
        async def t():
            await db.log_tcp("dup_strat", "d.com", "PASS", 100, 200)
            await db.log_tcp("dup_strat", "d.com", "FAIL", 5000, 0)
            working = await db.get_working_tcp("d.com")
            assert len(working) == 1, f"Should return 1 unique, got {len(working)}"
        asyncio.run(t())
