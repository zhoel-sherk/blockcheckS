"""Unit tests for lua-bridge edge cases and event handling."""

from __future__ import annotations

import errno
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from blockchecks.service.lua_bridge_ipc import BridgeEvent, BridgePaths, LuaBridge


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


class TestTornReadPublish:
    def test_publish_then_read_is_consistent(self, tmp_path):
        """After each publish, a fresh reader sees a consistent id/gen pair."""
        from blockchecks.service.lua_bridge_ipc import LuaBridge

        lb = LuaBridge("torn-ns", shm_base=tmp_path)
        lb.setup()
        for i in range(1, 6):
            lb.publish(i, i)
            assert lb.paths.strategy_id.read_text().strip() == str(i)
            assert lb.paths.strategy_gen.read_text().strip() == str(i)
            assert lb.paths.strategy_ready.read_text().strip() == str(i)
        lb.teardown()

    def test_drain_since_last_gen_does_not_lose_events(self, tmp_path):
        """Events filtered by gen >= since_gen survive repeated drains."""
        import json

        from blockchecks.service.lua_bridge_ipc import LuaBridge

        lb = LuaBridge("drain-ns", shm_base=tmp_path)
        lb.setup()
        with open(lb.paths.events, "a") as f:
            for i in range(1, 6):
                f.write(json.dumps({"event": "APPLIED", "id": i, "gen": i}) + "\n")
        # drain from gen 3: should see gens 3,4,5
        got = lb.drain_events(since_gen=3)
        assert [e.gen for e in got] == [3, 4, 5]
        # drain again with same since_gen — file unchanged, no loss
        got2 = lb.drain_events(since_gen=3)
        assert len(got2) == 3
        lb.teardown()


def test_world_writable_warning_includes_path_and_uid(tmp_path, caplog, monkeypatch):
    from blockchecks.service import lua_bridge_ipc as ipc

    ipc._world_warned.clear()
    ipc._setfacl_available = False
    path = tmp_path / "shm"
    path.mkdir()
    monkeypatch.setattr(ipc.os, "chmod", lambda *_a, **_k: None)
    monkeypatch.setattr(
        ipc.sp, "run", lambda *_a, **_k: SimpleNamespace(returncode=1, stderr="")
    )
    with caplog.at_level(logging.WARNING, logger=ipc.log.name):
        ipc._ipc_relax_for_nobody(path, is_dir=True)
    msg = " ".join(r.getMessage() for r in caplog.records)
    assert str(path) in msg
    assert str(ipc.NFQWS2_OVERFLOW_UID) in msg
    assert "world-writable" in msg


def test_ipc_relax_raises_when_all_chmod_paths_fail(tmp_path, monkeypatch):
    from blockchecks.service import lua_bridge_ipc as ipc

    ipc._setfacl_available = False
    path = tmp_path / "shm"
    path.mkdir()

    def fail_chmod(*_a, **_k):
        raise OSError(errno.EACCES, "chmod denied")

    monkeypatch.setattr(ipc.os, "chmod", fail_chmod)
    monkeypatch.setattr(
        ipc.sp,
        "run",
        lambda *_a, **_k: SimpleNamespace(returncode=1, stderr="sudo denied"),
    )
    with pytest.raises(ipc.IpcPermissionError, match="world-writable fallback all failed"):
        ipc._ipc_relax_for_nobody(path, is_dir=True)


def test_setfacl_probe_cached(monkeypatch):
    from blockchecks.service import lua_bridge_ipc as ipc

    ipc._setfacl_available = None
    calls: list[list[str]] = []

    def track_run(cmd, **_kw):
        calls.append(list(cmd))
        return SimpleNamespace(returncode=0, stderr=b"")

    monkeypatch.setattr(ipc.sp, "run", track_run)
    assert ipc._setfacl_usable() is True
    assert ipc._setfacl_usable() is True
    assert [c[0] for c in calls].count("setfacl") == 1
    assert calls[0][1] == "--version"


def test_rmtree_logged_warns_on_leftovers(tmp_path, caplog, monkeypatch):
    from blockchecks.service import lua_bridge_ipc as ipc

    leftover = tmp_path / "stuck"
    leftover.mkdir()
    monkeypatch.setattr(
        ipc.shutil,
        "rmtree",
        lambda *_a, **_k: None,
    )
    with caplog.at_level(logging.WARNING, logger=ipc.log.name):
        ipc._rmtree_logged(leftover, context="test")
    assert any("left leftovers" in r.getMessage() for r in caplog.records)


def test_publish_enospc_raises_ipc_publish_error(tmp_path, caplog, monkeypatch):
    import errno as errno_mod

    from blockchecks.service.lua_bridge_ipc import IpcPublishError, LuaBridge

    lb = LuaBridge("enospc-ns", shm_base=tmp_path)
    lb.setup()

    def enospc_write(*_a, **_k):
        raise OSError(errno_mod.ENOSPC, "No space left on device")

    monkeypatch.setattr(
        "blockchecks.service.lua_bridge_ipc.Path.write_text",
        enospc_write,
    )
    with caplog.at_level(logging.ERROR, logger="blockchecks.service.lua_bridge_ipc"):
        with pytest.raises(IpcPublishError, match="enospc-ns"):
            lb.publish(strategy_id=1, gen=1)
    assert any("ENOSPC" in r.getMessage() for r in caplog.records)
    lb.teardown()
