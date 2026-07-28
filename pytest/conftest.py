"""Shared fixtures for blockcheckS pytest tests."""
import os, sys, pytest, asyncio, tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.db_logger import StateDB
from engine.async_runner import AsyncTestRunner


@pytest.fixture(scope="function")
def temp_db():
    """Fresh SQLite database for each test."""
    db_path = tempfile.mktemp(suffix=".db")
    db = StateDB(db_path)
    asyncio.run(db.init())
    yield db
    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest.fixture(scope="function")
def runner():
    """AsyncTestRunner with pool_size=1 — yields sync, test must call asyncio."""
    r = AsyncTestRunner(pool_size=1)
    asyncio.run(r.start())
    yield r
    asyncio.run(r.stop())
