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
