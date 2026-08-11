"""Unit tests for voice_discovery — sing-box gateway/voice WS discovery."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from blockchecks.checkers.voice_discovery import (
    _load_guild_channel,
    discover_multiple,
    discover_voice_endpoint,
    load_token,
)

pytestmark = pytest.mark.unit


# ── load_token ────────────────────────────────────────────────────────


def test_load_token_missing_settings(tmp_path, monkeypatch):
    from blockchecks.checkers import voice_discovery as vd

    monkeypatch.setattr(vd, "DPI_TESTER_SETTINGS", str(tmp_path / "settings.ini"))
    assert load_token() is None


def test_load_token_world_writable(tmp_path, monkeypatch):
    import os

    from blockchecks.checkers import voice_discovery as vd

    settings = tmp_path / "settings.ini"
    settings.write_text("[discord]\ntoken=abc\n")
    os.chmod(settings, 0o666)
    monkeypatch.setattr(vd, "DPI_TESTER_SETTINGS", str(settings))
    assert load_token() is None


def test_load_token_ok(tmp_path, monkeypatch):
    import os

    from blockchecks.checkers import voice_discovery as vd

    settings = tmp_path / "settings.ini"
    settings.write_text("[discord]\ntoken=secret123\n")
    os.chmod(settings, 0o600)
    monkeypatch.setattr(vd, "DPI_TESTER_SETTINGS", str(settings))
    assert load_token() == "secret123"


def test_load_token_empty_falls_back_none(tmp_path, monkeypatch):
    import os

    from blockchecks.checkers import voice_discovery as vd

    settings = tmp_path / "settings.ini"
    settings.write_text("[discord]\nother=1\n")
    os.chmod(settings, 0o600)
    monkeypatch.setattr(vd, "DPI_TESTER_SETTINGS", str(settings))
    assert load_token() is None


# ── _load_guild_channel ───────────────────────────────────────────────


def test_load_guild_channel(tmp_path, monkeypatch):
    from blockchecks.checkers import voice_discovery as vd

    settings = tmp_path / "settings.ini"
    settings.write_text("[discord]\nguild_id=111\nchannel_id=222\n")
    monkeypatch.setattr(vd, "DPI_TESTER_SETTINGS", str(settings))
    assert _load_guild_channel() == ("111", "222")


# ── discover_voice_endpoint ───────────────────────────────────────────


def test_discover_voice_endpoint_no_token(monkeypatch):
    from blockchecks.checkers import voice_discovery as vd

    monkeypatch.setattr(vd, "load_token", lambda: None)
    assert asyncio.run(discover_voice_endpoint()) is None


def test_discover_voice_endpoint_no_singbox(monkeypatch):
    from blockchecks.checkers import voice_discovery as vd

    monkeypatch.setattr(vd, "load_token", lambda: "tok")

    class _CM:
        def __init__(self):
            self._val = None

        async def __aenter__(self):
            return None  # sing-box unavailable

        async def __aexit__(self, *a):
            return None

    monkeypatch.setattr(vd, "_singbox_session", lambda: _CM())
    assert asyncio.run(discover_voice_endpoint()) is None


def test_discover_voice_endpoint_gateway_exception(monkeypatch):
    from blockchecks.checkers import voice_discovery as vd

    monkeypatch.setattr(vd, "load_token", lambda: "tok")

    class _CM:
        def __init__(self):
            self._val = MagicMock()

        async def __aenter__(self):
            return object()

        async def __aexit__(self, *a):
            return None

    monkeypatch.setattr(vd, "_singbox_session", lambda: _CM())
    monkeypatch.setattr(vd, "_discover_via_gateway",
                        AsyncMock(side_effect=RuntimeError("boom")))
    assert asyncio.run(discover_voice_endpoint()) is None


# ── discover_multiple ─────────────────────────────────────────────────


def test_discover_multiple_dns_only(monkeypatch):
    from blockchecks.checkers import voice_discovery as vd

    monkeypatch.setattr(vd, "dns_discover",
                        AsyncMock(return_value=[{"ip": "35.1.2.3", "port": 50004,
                                                  "hostname": "h"}]))
    monkeypatch.setattr(vd, "load_token", lambda: None)
    eps = asyncio.run(discover_multiple(count=2, use_dns=True))
    assert len(eps) == 1
    assert eps[0]["ip"] == "35.1.2.3"


def test_discover_multiple_dns_fail_then_gateway(monkeypatch):
    from blockchecks.checkers import voice_discovery as vd

    monkeypatch.setattr(vd, "dns_discover",
                        AsyncMock(side_effect=RuntimeError("dns down")))
    monkeypatch.setattr(vd, "load_token", lambda: "tok")
    monkeypatch.setattr(vd, "discover_voice_endpoint",
                        AsyncMock(return_value={"ip": "9.9.9.9", "port": 50001,
                                                "voice_ws_endpoint": "ep"}))
    eps = asyncio.run(discover_multiple(count=1, use_dns=True))
    assert len(eps) == 1
    assert eps[0]["ip"] == "9.9.9.9"


def test_discover_multiple_use_dns_false(monkeypatch):
    from blockchecks.checkers import voice_discovery as vd

    monkeypatch.setattr(vd, "dns_discover", AsyncMock())
    monkeypatch.setattr(vd, "load_token", lambda: None)
    eps = asyncio.run(discover_multiple(count=2, use_dns=False))
    assert eps == []
    vd.dns_discover.assert_not_called()


# ── _manage_singbox / _singbox_session ────────────────────────────────


def test_manage_singbox_no_config(monkeypatch):
    import blockchecks.checkers.voice_discovery as vd

    monkeypatch.setattr(vd, "SING_BOX_CONFIG", "/nonexistent/config.json")
    assert vd._manage_singbox(True) is None
    vd._singbox_proc = None


def test_singbox_session_unavailable(monkeypatch):
    import blockchecks.checkers.voice_discovery as vd

    async def _go():
        vd._singbox_proc = None
        monkeypatch.setattr(vd, "_manage_singbox", lambda start: None)
        async with vd._singbox_session() as sb:
            assert sb is None

    asyncio.run(_go())


# ── _manage_singbox start/stop + session with running proxy ───────────


def test_manage_singbox_start_and_stop(monkeypatch, tmp_path):
    import subprocess

    import blockchecks.checkers.voice_discovery as vd

    conf = tmp_path / "config.json"
    conf.write_text("{}")
    proc = MagicMock()
    proc.poll.return_value = None
    monkeypatch.setattr(vd, "SING_BOX_CONFIG", str(conf))
    monkeypatch.setattr(vd, "SING_BOX_BIN", str(tmp_path / "sing-box"))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(vd.time, "sleep", lambda s: None)

    vd._singbox_proc = None
    started = vd._manage_singbox(True)
    assert started is proc
    assert vd._singbox_proc is proc

    vd._manage_singbox(False)
    assert vd._singbox_proc is None


def test_manage_singbox_restart_terminates_old(monkeypatch, tmp_path):
    import subprocess

    import blockchecks.checkers.voice_discovery as vd

    conf = tmp_path / "config.json"
    conf.write_text("{}")
    old = MagicMock()
    old.poll.return_value = None
    new = MagicMock()
    new.poll.return_value = None
    monkeypatch.setattr(vd, "SING_BOX_CONFIG", str(conf))
    monkeypatch.setattr(vd, "SING_BOX_BIN", str(tmp_path / "sing-box"))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: new)
    monkeypatch.setattr(vd.time, "sleep", lambda s: None)

    vd._singbox_proc = old
    started = vd._manage_singbox(True)
    assert started is new
    old.terminate.assert_called_once()
    vd._singbox_proc = None


def test_singbox_session_with_proxy(monkeypatch):
    import blockchecks.checkers.voice_discovery as vd

    async def _go():
        proc = MagicMock()
        monkeypatch.setattr(vd, "_manage_singbox", lambda start: proc if start else None)
        async with vd._singbox_session() as sb:
            assert sb is proc

    asyncio.run(_go())


# ── _discover_via_gateway (mocked aiohttp WS) ─────────────────────────


def test_discover_via_gateway_no_server_update():
    import asyncio
    from unittest.mock import patch

    from blockchecks.checkers.voice_discovery import _discover_via_gateway

    gw_msgs = [
        {"d": {"heartbeat_interval": 1000}},
        {"t": "READY", "d": {"user": {"id": "1"}}},
    ]

    class FakeWS:
        def __init__(self):
            self._msgs = list(gw_msgs)
            self.sent = []

        async def receive_json(self):
            if not self._msgs:
                raise asyncio.TimeoutError
            return self._msgs.pop(0)

        async def send_json(self, payload):
            self.sent.append(payload)

        async def close(self):
            return None

    gw_ws = FakeWS()

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        def ws_connect(self, url):
            async def _inner(*a, **k):
                return gw_ws

            return _inner()

    with patch("aiohttp_socks.ProxyConnector"), patch(
        "aiohttp.ClientSession",
        return_value=FakeSession()), patch(
        "blockchecks.engine.config.SOCKS5_PROXY",
        "socks5://127.0.0.1:1080"), patch(
        "blockchecks.checkers.voice_discovery._load_guild_channel",
        return_value=("", "")):
        result = asyncio.run(_discover_via_gateway("token"))
    assert result is None


def test_discover_multiple_gateway_layer(monkeypatch):
    import blockchecks.checkers.voice_discovery as vd

    monkeypatch.setattr(vd, "dns_discover", AsyncMock(return_value=[]))
    monkeypatch.setattr(vd, "load_token", lambda: "tok")
    monkeypatch.setattr(vd, "discover_voice_endpoint",
                        AsyncMock(return_value={"ip": "9.9.9.9", "port": 50001,
                                                "voice_ws_endpoint": "ep"}))
    eps = asyncio.run(discover_multiple(count=1, use_dns=True))
    assert eps and eps[0]["ip"] == "9.9.9.9"


def test_discover_multiple_gateway_exception(monkeypatch):
    import blockchecks.checkers.voice_discovery as vd

    monkeypatch.setattr(vd, "dns_discover", AsyncMock(return_value=[]))
    monkeypatch.setattr(vd, "load_token", lambda: "tok")
    monkeypatch.setattr(vd, "discover_voice_endpoint",
                        AsyncMock(side_effect=RuntimeError("down")))
    eps = asyncio.run(discover_multiple(count=1, use_dns=True))
    assert eps == []
