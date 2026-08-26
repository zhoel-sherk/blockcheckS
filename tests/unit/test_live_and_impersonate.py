"""Unit tests for live_events journal, daemon heartbeat, impersonate target."""

from __future__ import annotations

import os
import time

import pytest

from blockchecks.checkers.curl_probe import DEFAULT_IMPERSONATE, impersonate_target
from blockchecks.service import live_events
from blockchecks.service.lua_bridge_ipc import LuaBridge


@pytest.mark.unit
def test_impersonate_target_default_and_env(monkeypatch) -> None:
    monkeypatch.delenv("BLOCKCHECKS_IMPERSONATE", raising=False)
    assert impersonate_target() == DEFAULT_IMPERSONATE == "chrome124"
    monkeypatch.setenv("BLOCKCHECKS_IMPERSONATE", "chrome")
    assert impersonate_target() == "chrome"
    monkeypatch.setenv("BLOCKCHECKS_IMPERSONATE", "  ")
    assert impersonate_target() == DEFAULT_IMPERSONATE


@pytest.mark.unit
def test_heartbeat_age_missing_and_stale(tmp_path) -> None:
    bridge = LuaBridge("bs-p-hb", shm_base=tmp_path)
    bridge.setup()
    # no heartbeat yet -> unknown (None), NOT stale-by-value
    assert bridge.heartbeat_age() is None

    now = time.time()
    bridge.paths.heartbeat.write_text(f"{int(now - 10)}\n", encoding="utf-8")
    age = bridge.heartbeat_age(now=now)
    assert age is not None and 9.0 <= age <= 11.0

    bridge.paths.heartbeat.write_text("garbage\n", encoding="utf-8")
    assert bridge.heartbeat_age() is None
    bridge.teardown()


@pytest.mark.unit
def test_live_events_write_read_filter(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(live_events, "RUNTIME_LOGS_DIR", tmp_path)

    live_events.set_current(
        domain="discord.com", strategy="std_fake", ns="bs-p-0", backend="lua_bridge"
    )
    cur_data = live_events.read_current()
    assert cur_data is not None and cur_data["domain"] == "discord.com"
    assert cur_data["backend"] == "lua_bridge"
    assert live_events.writer_current_path().is_file()

    for i in range(3):
        live_events.write_probe(
            domain="discord.com" if i < 2 else "youtube.com",
            strategy=f"strat_{i}",
            ns=f"bs-p-{i}",
            backend="lua_bridge",
            status="PASS",
            http_code=200,
            latency_ms=100 + i,
            applied=True,
        )
    all_recs = live_events.tail_events(limit=10)
    assert len(all_recs) == 3
    assert [r["strategy"] for r in all_recs] == ["strat_0", "strat_1", "strat_2"]

    filtered = live_events.tail_events(limit=10, domain="discord.com")
    assert len(filtered) == 2 and all(r["domain"] == "discord.com" for r in filtered)

    limited = live_events.tail_events(limit=1)
    assert len(limited) == 1 and limited[0]["strategy"] == "strat_2"


@pytest.mark.unit
def test_live_events_suffix_and_latest_path(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(live_events, "RUNTIME_LOGS_DIR", tmp_path)
    legacy = tmp_path / "events_live.jsonl"
    legacy.write_text('{"domain":"legacy","status":"PASS"}\n', encoding="utf-8")
    suffixed = tmp_path / "events_live.9999.jsonl"
    suffixed.write_text('{"domain":"newest","status":"PASS"}\n', encoding="utf-8")
    os.utime(suffixed, (10, 10))
    os.utime(legacy, (1, 1))

    assert live_events.latest_events_path() == suffixed
    recs = live_events.tail_events()
    assert len(recs) == 1 and recs[0]["domain"] == "newest"


@pytest.mark.unit
def test_live_events_empty_and_torn_lines(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(live_events, "RUNTIME_LOGS_DIR", tmp_path)
    assert live_events.tail_events() == []
    ev = live_events.writer_events_path()
    ev.write_text('{"domain":"a.com","status":"PASS"}\nTORN LINE\n', encoding="utf-8")
    recs = live_events.tail_events()
    assert len(recs) == 1 and recs[0]["domain"] == "a.com"
