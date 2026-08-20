"""Find a Discord voice UDP endpoint through a sing-box SOCKS5 proxy.
With a token: Gateway WS then Voice WS OP2 Ready. Without a token: caller uses a static IP.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from blockchecks.checkers.voice_dns import discover_voice_endpoints as dns_discover
from blockchecks.engine.config import (
    DPI_TESTER_SETTINGS,
    SING_BOX_BIN,
    SING_BOX_CONFIG,
    SOCKS5_PROXY,
)

log = logging.getLogger(__name__)


_singbox_lock = threading.Lock()
_singbox_proc: subprocess.Popen | None = None


def _manage_singbox(start: bool) -> subprocess.Popen | None:
    """Start/stop sing-box under a process-wide lock (H8 concurrent-safe)."""
    global _singbox_proc
    with _singbox_lock:
        if start:
            if _singbox_proc is not None:
                try:
                    _singbox_proc.terminate()
                    _singbox_proc.wait(timeout=2)
                except Exception:
                    pass
                _singbox_proc = None
            if not os.path.exists(SING_BOX_CONFIG):
                return None
            _singbox_proc = subprocess.Popen(
                [SING_BOX_BIN, "run", "-c", SING_BOX_CONFIG],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(2)
            return _singbox_proc
        if _singbox_proc is not None:
            try:
                _singbox_proc.terminate()
                _singbox_proc.wait(timeout=2)
            except Exception:
                pass
            _singbox_proc = None
        return None


@asynccontextmanager
async def _singbox_session() -> AsyncIterator[subprocess.Popen | None]:
    """Async CM: start sing-box for discovery, always stop on exit."""
    log.info("[discovery] Starting sing-box proxy...")
    sb = await asyncio.to_thread(_manage_singbox, True)
    if not sb:
        log.info("[discovery] sing-box unavailable — using static IP")
        yield None
        return
    try:
        yield sb
    finally:
        await asyncio.to_thread(_manage_singbox, False)
        log.info("[discovery] sing-box stopped")


def load_token() -> str | None:
    settings = DPI_TESTER_SETTINGS
    if not os.path.exists(settings):
        return None
    try:
        mode = os.stat(settings).st_mode
    except OSError:
        return None
    if mode & 0o002:
        log.warning("%s", f"[discovery] WARNING: refusing world-writable settings file: {settings}")
        return None
    import configparser as cp

    cfg = cp.ConfigParser(
        interpolation=None,
        delimiters=("=",),
        comment_prefixes=("#", ";"),
        inline_comment_prefixes=("#", ";"),
    )
    cfg.optionxform = str
    cfg.read(settings, encoding="utf-8")
    return cfg.get("discord", "token", fallback="") or None


def _load_guild_channel() -> tuple[str, str]:
    import configparser as cp

    cfg = cp.ConfigParser(
        interpolation=None,
        delimiters=("=",),
        comment_prefixes=("#", ";"),
        inline_comment_prefixes=("#", ";"),
    )
    cfg.optionxform = str
    cfg.read(DPI_TESTER_SETTINGS, encoding="utf-8")
    return (
        cfg.get("discord", "guild_id", fallback=""),
        cfg.get("discord", "channel_id", fallback=""),
    )


async def discover_voice_endpoint() -> dict | None:
    """Auto-discover Discord voice server via sing-box proxy.

    Returns dict with keys: ip, port, ssrc, voice_ws_endpoint
    Returns None if token missing, proxy unavailable, or discovery fails.
    """
    token = load_token()
    if not token:
        return None

    async with _singbox_session() as sb:
        if not sb:
            return None
        try:
            return await _discover_via_gateway(token)
        except Exception as e:
            log.info("%s", f"[discovery] Failed: {e}")
            return None


async def _discover_via_gateway(token: str) -> dict | None:
    import aiohttp
    from aiohttp_socks import ProxyConnector

    connector = ProxyConnector.from_url(SOCKS5_PROXY)
    timeout = aiohttp.ClientTimeout(total=30, connect=10)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        ws = await asyncio.wait_for(
            session.ws_connect("wss://gateway.discord.gg/?encoding=json&v=10"),
            timeout=10,
        )
        hello = await asyncio.wait_for(ws.receive_json(), 10)
        hi = hello["d"]["heartbeat_interval"] / 1000
        guild_id, channel_id = _load_guild_channel()

        async def hb() -> None:
            while True:
                await asyncio.sleep(hi)
                try:
                    await ws.send_json({"op": 1, "d": None})
                except Exception:
                    break

        hbt = asyncio.create_task(hb())
        await ws.send_json(
            {
                "op": 2,
                "d": {
                    "token": token,
                    "properties": {"os": "linux", "browser": "chrome", "device": "pc"},
                    "intents": 513,
                },
            }
        )

        voice_endpoint = ""
        voice_token_shard = ""
        user_id = ""
        session_id = ""
        got_session = False
        got_server = False
        t0 = asyncio.get_event_loop().time()

        try:
            while True:
                try:
                    msg = await asyncio.wait_for(ws.receive_json(), 15)
                except asyncio.TimeoutError:
                    break

                match msg:
                    case {"t": "READY", "d": {"user": {"id": str(uid)}}}:
                        user_id = uid
                        if guild_id and channel_id:
                            await ws.send_json(
                                {
                                    "op": 4,
                                    "d": {
                                        "guild_id": guild_id,
                                        "channel_id": channel_id,
                                        "self_mute": True,
                                        "self_deaf": True,
                                    },
                                }
                            )
                    case {"t": "VOICE_STATE_UPDATE", "d": dict(d)}:
                        session_id = d.get("session_id", "")
                        got_session = bool(session_id)
                    case {
                        "t": "VOICE_SERVER_UPDATE",
                        "d": {"endpoint": str(ep), "token": str(tok)},
                    }:
                        voice_endpoint = ep
                        voice_token_shard = tok
                        got_server = True
                    case _:
                        pass

                if got_session and got_server:
                    break
                if asyncio.get_event_loop().time() - t0 > 25:
                    break
        finally:
            hbt.cancel()
            await ws.close()

        if not voice_endpoint or not voice_token_shard:
            return None

        parts = voice_endpoint.rsplit(":", 1)
        v_host = parts[0]
        v_port = int(parts[1]) if len(parts) > 1 else 443
        vws = await asyncio.wait_for(
            session.ws_connect(f"wss://{v_host}:{v_port}/?v=4"), timeout=10
        )
        await asyncio.wait_for(vws.receive_json(), 10)
        await vws.send_json(
            {
                "op": 0,
                "d": {
                    "server_id": guild_id,
                    "user_id": user_id,
                    "session_id": session_id,
                    "token": voice_token_shard,
                },
            }
        )

        result: dict = {}
        op9_retries = 0
        v_t0 = asyncio.get_event_loop().time()
        try:
            while True:
                vmsg = await asyncio.wait_for(vws.receive_json(), 10)
                match vmsg:
                    case {"op": 2, "d": dict(vd)}:
                        result = {
                            "ip": vd.get("ip", ""),
                            "port": vd.get("port", 0),
                            "ssrc": vd.get("ssrc", 1),
                            "voice_ws_endpoint": voice_endpoint,
                        }
                        break
                    case {"op": 9} if op9_retries < 2:
                        op9_retries += 1
                        await vws.send_json(
                            {
                                "op": 0,
                                "d": {
                                    "server_id": guild_id,
                                    "user_id": user_id,
                                    "session_id": "" if op9_retries > 1 else session_id,
                                    "token": voice_token_shard,
                                },
                            }
                        )
                    case {"op": 9}:
                        break
                    case _ if asyncio.get_event_loop().time() - v_t0 > 15:
                        break
                    case _:
                        pass
        finally:
            await vws.close()

        if result:
            log.info(
                "%s",
                f"[discovery] Voice server: {result['ip']}:{result['port']} (SSRC={result['ssrc']})",
            )
        return result or None


async def discover_multiple(
    count: int = 5, use_dns: bool = True, use_cache: bool = True
) -> list[dict]:
    """Discover N Discord voice UDP endpoints.

    DNS: finland{N}.discord.gg bulk resolution (no auth).
    Gateway: WS then OP2 Ready (needs token).
    Cache: endpoints already stored.

    Returns: [{"ip": str, "port": int, "hostname": str}, ...]
    """
    endpoints = []
    seen_ips: set[str] = set()

    if use_dns:
        try:
            dns_eps = await dns_discover(count, use_cache=use_cache)
            for ep in dns_eps:
                ip = ep.get("ip", "")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    endpoints.append(ep)
        except Exception as e:
            log.info("%s", f"[discovery] DNS layer failed: {e}")

    if len(endpoints) >= count:
        return endpoints[:count]

    token = load_token()
    if token and len(endpoints) < count:
        log.info("%s", f"[discovery] Gateway layer (up to {count - len(endpoints)} more)...")
        for _ in range(min(count - len(endpoints), 3)):
            try:
                ep = await discover_voice_endpoint()
                if ep and ep.get("ip") and ep["ip"] not in seen_ips:
                    seen_ips.add(ep["ip"])
                    endpoints.append(
                        {
                            "ip": ep["ip"],
                            "port": ep["port"],
                            "hostname": ep.get("voice_ws_endpoint", ""),
                        }
                    )
            except Exception as e:
                log.info("%s", f"[discovery] Gateway attempt failed: {e}")
                break

    return endpoints[:count]
