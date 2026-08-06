"""Unit tests for lua-bridge edge cases and event handling."""

from __future__ import annotations

import json
from pathlib import Path

from blockchecks.engine.services.lua_bridge import BridgeEvent, BridgePaths, LuaBridge


class TestBridgeEventParsing:
    def test_valid_applied_event(self):
        line = json.dumps({"event": "APPLIED", "id": 7, "gen": 42})
        evt = BridgeEvent.from_line(line)
        assert evt is not None
        assert evt.event == "APPLIED"
        assert evt.gen == 42
        assert evt.id == 7

    def test_valid_fail_event(self):
        line = json.dumps({"event": "STRATEGY_FAIL", "reason": "retrans", "gen": 5})
        evt = BridgeEvent.from_line(line)
        assert evt is not None
        assert evt.event == "STRATEGY_FAIL"
        assert evt.reason == "retrans"
        assert evt.gen == 5

    def test_invalid_json_returns_none(self):
        assert BridgeEvent.from_line("not json") is None
        assert BridgeEvent.from_line("") is None
        assert BridgeEvent.from_line("{broken") is None

    def test_event_without_gen(self):
        line = json.dumps({"event": "APPLIED", "id": 1})
        evt = BridgeEvent.from_line(line)
        assert evt is not None
        assert evt.gen == 0


class TestLuaBridgeDrain:
    def test_drain_events_since_gen(self, tmp_path):
        lb = LuaBridge("test-ns", shm_base=tmp_path)
        lb.setup()
        events = [
            {"event": "APPLIED", "id": 1, "gen": 10},
            {"event": "APPLIED", "id": 2, "gen": 11},
            {"event": "STRATEGY_FAIL", "reason": "retrans", "gen": 12},
            {"event": "APPLIED", "id": 2, "gen": 13},
        ]
        with open(lb.paths.events, "a") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        result = lb.drain_events(since_gen=12)
        assert len(result) == 2
        assert result[0].gen == 12
        assert result[0].event == "STRATEGY_FAIL"
        assert result[1].gen == 13
        assert result[1].event == "APPLIED"
        lb.teardown()

    def test_drain_events_empty_file(self, tmp_path):
        lb = LuaBridge("test-ns", shm_base=tmp_path)
        lb.setup()
        result = lb.drain_events()
        assert result == []
        lb.teardown()

    def test_drain_events_no_file(self, tmp_path):
        lb = LuaBridge("nonexistent-ns", shm_base=tmp_path)
        # Don't setup — no directory
        result = lb.drain_events()
        assert result == []

    def test_strategy_fail_events_emitted(self, tmp_path):
        lb = LuaBridge("test-ns", shm_base=tmp_path)
        lb.setup()
        events = [
            {"event": "STRATEGY_FAIL", "reason": "retrans", "gen": 1},
            {"event": "STRATEGY_FAIL", "reason": "rst_in", "gen": 2},
        ]
        with open(lb.paths.events, "a") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        result = lb.drain_events(since_gen=0)
        assert len(result) == 2
        fail_events = [e for e in result if e.event == "STRATEGY_FAIL"]
        assert len(fail_events) == 2


class TestLuaBridgePublish:
    def test_publish_writes_id_and_gen(self, tmp_path):
        lb = LuaBridge("test-ns", shm_base=tmp_path)
        lb.setup()
        lb.publish(strategy_id=42, gen=7)
        assert lb.paths.strategy_id.read_text().strip() == "42"
        assert lb.paths.strategy_gen.read_text().strip() == "7"
        lb.teardown()

    def test_publish_overwrites_previous(self, tmp_path):
        lb = LuaBridge("test-ns", shm_base=tmp_path)
        lb.setup()
        lb.publish(strategy_id=1, gen=1)
        lb.publish(strategy_id=2, gen=2)
        assert lb.paths.strategy_id.read_text().strip() == "2"
        assert lb.paths.strategy_gen.read_text().strip() == "2"
        lb.teardown()

    def test_publish_creates_ready_file(self, tmp_path):
        lb = LuaBridge("test-ns", shm_base=tmp_path)
        lb.setup()
        lb.publish(strategy_id=1, gen=1)
        assert lb.paths.strategy_ready.exists()
        lb.teardown()

    def test_setup_creates_shm_dir(self, tmp_path):
        lb = LuaBridge("test-ns", shm_base=tmp_path)
        lb.setup()
        assert lb.paths.base.is_dir()
        lb.teardown()
        assert not lb.paths.base.exists()

    def test_truncate_events_clears_file(self, tmp_path):
        lb = LuaBridge("test-ns", shm_base=tmp_path)
        lb.setup()
        with open(lb.paths.events, "a") as f:
            f.write(json.dumps({"event": "APPLIED", "id": 1, "gen": 1}) + "\n")
        lb.truncate_events()
        assert lb.paths.events.read_text() == ""
        lb.teardown()


class TestBridgePaths:
    def test_properties(self):
        bp = BridgePaths(base=Path("/dev/shm/blockchecks/bs-p-0"))
        assert bp.strategy_id == Path("/dev/shm/blockchecks/bs-p-0/strategy.id")
        assert bp.strategy_gen == Path("/dev/shm/blockchecks/bs-p-0/strategy.gen")
        assert bp.strategy_cmd == Path("/dev/shm/blockchecks/bs-p-0/strategy.cmd")
        assert bp.strategy_ready == Path("/dev/shm/blockchecks/bs-p-0/strategy.ready")
        assert bp.events == Path("/dev/shm/blockchecks/bs-p-0/events.ndjson")
