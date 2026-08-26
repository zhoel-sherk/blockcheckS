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
from blockchecks.engine.store import open_run_store


@pytest.fixture
def temp_db(tmp_path):
    """Fresh SQLite DB under pytest tmp_path."""
    db_path = tmp_path / "state.db"
    db = open_run_store(db_path)
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

    def fake_tcp(
        ns_name,
        strategy,
        domain,
        timeout,
        is_config=False,
        python_bin=None,
        disable_ech=False,
        *args,
        **kwargs,
    ):
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

    def fake_udp(
        ns_name, strategy, ip, port, timeout, is_config=False, python_bin=None, coexist=False
    ):
        return {
            "success": True,
            "latency_ms": 8.0,
            "detail": "ok",
        }

    monkeypatch.setattr("blockchecks.engine.async_runner._run_tcp_check", fake_tcp)
    monkeypatch.setattr("blockchecks.engine.async_runner._run_udp_check", fake_udp)
    monkeypatch.setattr("blockchecks.engine.async_runner._nfqws2_daemon", lambda *a, **k: None)
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
    config.addinivalue_line("markers", "integration: needs linux+sudo+nfqws2")


@pytest.fixture(autouse=True)
def _reset_engine_caches():
    """QA-7: drop settings/ipset lru_cache between tests (pytest-randomly order)."""
    from blockchecks.engine.ipset_catalog import clear_ipset_caches
    from blockchecks.engine.settings import clear_settings_cache

    clear_settings_cache()
    clear_ipset_caches()
    yield
    clear_settings_cache()
    clear_ipset_caches()


@pytest.fixture
def operator_logs(tmp_path, monkeypatch, capsys):
    """Attach INFO operator handlers so capsys sees log.info output.

    Depends on *capsys* so StreamHandler binds to the captured stdout/stderr.
    """
    import logging

    from blockchecks.engine.log import configure_logging

    monkeypatch.setattr("blockchecks.engine.log.RUNTIME_LOGS_DIR", tmp_path)
    root = logging.getLogger("blockchecks")
    saved_handlers = list(root.handlers)
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    try:
        configure_logging(level=logging.INFO)
        yield
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
            handler.close()
        for handler in saved_handlers:
            root.addHandler(handler)


@pytest.fixture
def nfqws2_available():
    """Skip integration if nfqws2 binary missing."""
    from blockchecks.engine.config import NFQWS2_BIN

    if not os.path.exists(NFQWS2_BIN):
        pytest.skip(f"nfqws2 not available: {NFQWS2_BIN}")
    return NFQWS2_BIN


@pytest.fixture(autouse=True)
def _live_events_tmp(monkeypatch, tmp_path):
    """Redirect live-journal files to tmp: unit tests must not write the
    real state-dir journal/current-probe files."""
    import blockchecks.service.live_events as le

    monkeypatch.setattr(le, "RUNTIME_LOGS_DIR", tmp_path)
    monkeypatch.setattr(le, "EVENTS_FILE", tmp_path / "events_live.jsonl")
    monkeypatch.setattr(le, "CURRENT_FILE", tmp_path / "current_probe.json")
    yield
