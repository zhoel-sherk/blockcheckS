"""Unit tests for lua_bridge IPC and conf builder."""

from __future__ import annotations

from pathlib import Path

import pytest

from blockchecks.service.lua_bridge_ipc import BridgeEvent, LuaBridge
from blockchecks.service.lua_conf import build_bridge_conf
from blockchecks.service.lua_session import chunk_strategies


@pytest.mark.unit
def test_publish_atomic_and_drain_events(tmp_path: Path) -> None:
    bridge = LuaBridge("bs-p-test", shm_base=tmp_path)
    bridge.setup()
    bridge.publish(7, 42)
    bridge.publish(8, 43)

    assert bridge.paths.strategy_id.read_text() == "8\n"
    assert bridge.paths.strategy_gen.read_text() == "43\n"
    assert bridge.paths.strategy_ready.read_text() == "43\n"

    bridge.paths.events.write_text(
        '{"event":"APPLIED","id":7,"gen":42}\n{"event":"APPLIED","id":8,"gen":43}\n',
        encoding="utf-8",
    )
    ev42 = bridge.drain_events(since_gen=42)
    assert len(ev42) == 2
    assert ev42[0].event == "APPLIED" and ev42[0].gen == 42

    ev43 = bridge.drain_events(since_gen=43)
    assert len(ev43) == 1 and ev43[0].gen == 43

    bridge.teardown()
    assert not bridge.paths.base.exists()


@pytest.mark.unit
def test_bridge_event_from_line() -> None:
    ev = BridgeEvent.from_line('{"event":"STRATEGY_FAIL","gen":5,"reason":"retrans"}')
    assert ev is not None
    assert ev.event == "STRATEGY_FAIL"
    assert ev.gen == 5
    assert ev.reason == "retrans"
    assert BridgeEvent.from_line("not json") is None


@pytest.mark.unit
def test_build_bridge_conf_strategy_numbering(tmp_path: Path) -> None:
    ipc = tmp_path / "bs-p-0"
    strategies = [
        "fake:blob=stun:repeats=6:tcp_ts=-1000",
        "fake:blob=max_ru:repeats=6:tcp_ts=-1000",
    ]
    conf = build_bridge_conf(strategies, ipc, protocol="tls12")
    assert f"--writable={ipc}" in conf
    assert "--lua-desync=bs_poll_strategy" in conf
    assert "--lua-desync=scan_pick" in conf
    assert ":strategy=1" in conf
    assert ":strategy=2" in conf
    assert conf.count("--lua-desync=fake:") >= 2


@pytest.mark.unit
def test_chunk_strategies_respects_batch_cap() -> None:
    items = list(range(10))
    chunks = chunk_strategies(items, 3)
    assert chunks == [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9]]


@pytest.mark.unit
def test_build_bridge_conf_stages_lua_under_ipc(tmp_path: Path) -> None:
    ipc = tmp_path / "bs-p-0"
    strategies = ["fake:blob=stun:repeats=6:tcp_ts=-1000"]
    conf = build_bridge_conf(strategies, ipc, protocol="tls12")
    assert f"--writable={ipc}" in conf
    staged = ipc / "lua" / "write_ipc.lua"
    assert staged.is_file()
    assert f"--lua-init=@{staged}" in conf


@pytest.mark.unit
def test_build_bridge_conf_http_protocol(tmp_path: Path) -> None:
    ipc = tmp_path / "bs-p-http"
    conf = build_bridge_conf(
        ["fake:blob=stun:repeats=6:tcp_ts=-1000"],
        ipc,
        protocol="http",
    )
    assert "--payload=http_req" in conf
    assert "--lua-desync=scan_pick" in conf


@pytest.mark.unit
def test_build_bridge_conf_quic_protocol(tmp_path: Path) -> None:
    ipc = tmp_path / "bs-p-quic"
    conf = build_bridge_conf(
        ["fake:blob=fake_default_quic:repeats=6"],
        ipc,
        protocol="quic",
    )
    assert "--filter-udp=443" in conf
    assert "--filter-l7=quic" in conf
    assert "--payload=quic_initial" in conf
    assert "--lua-desync=scan_pick" in conf


@pytest.mark.unit
def test_scan_bridge_lua_accepts_http_req() -> None:
    from blockchecks.engine.config import get_blockchecks_lua_scripts

    lua = next(p for p in get_blockchecks_lua_scripts() if p.name == "scan_bridge.lua")
    text = lua.read_text(encoding="utf-8")
    assert "http_req" in text
    assert "quic_initial" in text
    assert "bs_l7_ok" in text


@pytest.mark.unit
def test_events_file_world_writable_for_dropped_uid(tmp_path: Path) -> None:
    """Nfqws2 drops privileges after init; events.ndjson must be 0666
    so Lua can append APPLIED/STRATEGY_FAIL events (644 root file → silent loss)."""
    bridge = LuaBridge("bs-p-uid", shm_base=tmp_path)
    bridge.setup()
    assert (bridge.paths.events.stat().st_mode & 0o777) == 0o666
    bridge.truncate_events()
    assert (bridge.paths.events.stat().st_mode & 0o777) == 0o666
    bridge.teardown()


@pytest.mark.unit
def test_bridge_writable_dir_world_writable_for_dropped_uid(tmp_path: Path) -> None:
    """nfqws2 runs as nobody (65534) after setuid; it must chdir + create
    .staging/strategy.* inside the writable dir. root:root 0755 lets it chdir
    but NOT create files → daemon dies / APPLIED never written. Must be 0777."""
    bridge = LuaBridge("bs-p-wd", shm_base=tmp_path)
    bridge.setup()
    assert (bridge.paths.base.stat().st_mode & 0o777) == 0o777
    bridge.teardown()


@pytest.mark.unit
def test_published_strategy_files_world_writable(tmp_path: Path) -> None:
    """Published strategy.id/ready must be 0666 so the dropped-uid nfqws2
    process can rewrite them between batches."""
    bridge = LuaBridge("bs-p-pub", shm_base=tmp_path)
    bridge.setup()
    bridge.publish(1, 7, "fake:blob=stun:repeats=6")
    for name in ("strategy.id", "strategy.gen", "strategy.ready", "strategy.cmd"):
        p = bridge.paths.base / name
        assert p.is_file(), name
        assert (p.stat().st_mode & 0o777) == 0o666, name
    bridge.teardown()


@pytest.mark.unit
def test_lua_scripts_exist_in_repo() -> None:
    from blockchecks.engine.config import get_blockchecks_lua_scripts

    paths = get_blockchecks_lua_scripts()
    assert len(paths) >= 4
    names = {p.name for p in paths}
    assert "write_ipc.lua" in names
    assert "scan_bridge.lua" in names
    assert "init.lua" in names
    assert "geneva.lua" in names


def test_build_bridge_conf_escapes_lt(tmp_path: Path) -> None:
    """nfqws2 conf splitter rejects a bare '<' — it must be escaped."""
    from blockchecks.engine.conf_builder import escape_conf_lt
    from blockchecks.service.lua_conf import build_bridge_conf

    assert escape_conf_lt("--out-range=s1<d1") == "--out-range=s1\\<d1"

    ipc = tmp_path / "ipc"
    ipc.mkdir()
    conf = build_bridge_conf(
        ["--payload=empty --out-range=s1<d1\npktmod:ip_ttl=1"],
        ipc,
        protocol="tls12",
    )
    assert "--out-range=s1\\<d1" in conf
    assert "--out-range=s1<d1" not in conf
    assert "--lua-desync=pktmod:ip_ttl=1:strategy=1" in conf
