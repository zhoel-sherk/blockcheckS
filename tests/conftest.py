"""Shared fixtures for blockcheckS tests."""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from blockchecks.engine.async_runner import AsyncTestRunner
from blockchecks.engine.db_logger import StateDB


@pytest.fixture
def temp_db(tmp_path):
    """Fresh SQLite DB under pytest tmp_path."""
    db_path = tmp_path / "state.db"
    db = StateDB(str(db_path))
    asyncio.run(db.init())
    return db


@pytest.fixture
def mock_pool(monkeypatch):
    """Fake NetNsPool — no root / netns."""
    names = ["mock-ns-0", "mock-ns-1", "mock-ns-2", "mock-ns-3"]
    q: asyncio.Queue = None

    class FakePool:
        def __init__(self, size=4, base="bs-p"):
            self.size = size
            self.base = base
            self._created = False
            self._names = names[:size]

        def create_all(self):
            self._created = True

        def destroy_all(self):
            self._created = False

        async def seed(self):
            nonlocal q
            q = asyncio.Queue()
            for n in self._names:
                await q.put(n)

        async def drain(self):
            nonlocal q
            if q is None:
                return
            while not q.empty():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    break

        async def acquire(self):
            return await q.get()

        async def release(self, ns_name: str):
            await q.put(ns_name)

    monkeypatch.setattr("blockchecks.engine.async_runner.NetNsPool", FakePool)
    return FakePool


@pytest.fixture
def mock_tcp_udp(monkeypatch):
    """Mock probe workers so pair/resume tests need no netns."""

    def fake_tcp(ns_name, strategy, domain, timeout, is_config=False,
                 python_bin=None, disable_ech=False):
        return {
            "success": True,
            "http_code": 200,
            "latency_ms": 12.0,
            "content_len": 500,
            "content_ok": True,
            "error": None,
            "throttled": False,
            "read_rate_bps": 500000.0,
        }

    def fake_udp(ns_name, strategy, ip, port, timeout, is_config=False,
                 python_bin=None, coexist=False):
        return {
            "success": True,
            "latency_ms": 8.0,
            "detail": "ok",
        }

    monkeypatch.setattr("blockchecks.engine.async_runner._run_tcp_check", fake_tcp)
    monkeypatch.setattr("blockchecks.engine.async_runner._run_udp_check", fake_udp)
    monkeypatch.setattr(
        "blockchecks.engine.async_runner._nfqws2_daemon", lambda *a, **k: None
    )
    return {"tcp": fake_tcp, "udp": fake_udp}


@pytest.fixture
async def mock_runner(mock_pool, mock_tcp_udp, temp_db):
    """AsyncTestRunner with mocked pool + probes."""
    runner = AsyncTestRunner(pool_size=2, db=temp_db)
    await runner.start()
    yield runner
    await runner.stop()


def pytest_configure(config):
    config.addinivalue_line("markers", "unit: no root/netns")
    config.addinivalue_line(
        "markers", "integration: needs linux+sudo+nfqws2"
    )


@pytest.fixture
def nfqws2_available():
    """Skip integration if nfqws2 binary missing."""
    from blockchecks.engine.config import NFQWS2_BIN
    if not os.path.exists(NFQWS2_BIN):
        pytest.skip(f"nfqws2 not available: {NFQWS2_BIN}")
    return NFQWS2_BIN
