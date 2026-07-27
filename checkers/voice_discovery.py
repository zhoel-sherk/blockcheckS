"""Voice endpoint auto-discovery via sing-box SOCKS5 proxy.

Flow (with token):
  1. Start sing-box proxy
  2. Gateway WS → VOICE_SERVER_UPDATE → endpoint
  3. Voice WS → OP0 Identify → OP2 Ready → IP + UDP port + SSRC
  4. Stop sing-box

Flow (without token):
  Returns None → caller uses static IP fallback.

Storage: non-sensitive state in /tmp/blockcheckS_discovery.json
"""

import asyncio
import json
import os
import subprocess
import time
from typing import Optional

SING_BOX = "/usr/local/bin/sing-box"
SING_BOX_CONFIG = os.path.expanduser("~/.config/sing-box/config.json")
PROXY_URL = "socks5://127.0.0.1:11080"


def _manage_singbox(start: bool) -> Optional[subprocess.Popen]:
    """Start or stop sing-box proxy."""
    if start:
        subprocess.run(["pkill", "-f", "sing-box"], capture_output=True)
        time.sleep(0.5)
        if not os.path.exists(SING_BOX_CONFIG):
            return None
        proc = subprocess.Popen(
            [SING_BOX, "run", "-c", SING_BOX_CONFIG],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(2)
        return proc
    else:
        subprocess.run(["pkill", "-f", "sing-box"], capture_output=True)
        return None


def load_token() -> Optional[str]:
    """Load Discord token from dpi-tester settings.ini."""
    settings = "/home/zhoel/workspace/dpi-tester/settings.ini"
    if not os.path.exists(settings):
        return None
    import configparser as cp
    cfg = cp.ConfigParser(interpolation=None, delimiters=("=",),
                           comment_prefixes=("#", ";"),
                           inline_comment_prefixes=("#", ";"))
    cfg.optionxform = str
    cfg.read(settings, encoding="utf-8")
    return cfg.get("discord", "token", fallback="") or None


async def discover_voice_endpoint() -> Optional[dict]:
    """Auto-discover Discord voice server via sing-box proxy.

    Returns dict with keys: ip, port, ssrc, voice_ws_endpoint
    Returns None if token missing, proxy unavailable, or discovery fails.
    """
    token = load_token()
    if not token:
        return None

    # Start proxy
    print("[discovery] Starting sing-box proxy...")
    sb = _manage_singbox(True)
    if not sb:
        print("[discovery] sing-box unavailable — using static IP")
        return None

    try:
        from aiohttp_socks import ProxyConnector
        import aiohttp

        connector = ProxyConnector.from_url(PROXY_URL)
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        session = aiohttp.ClientSession(timeout=timeout, connector=connector)

        try:
            # ── Gateway WS ──
            ws = await asyncio.wait_for(
                session.ws_connect("wss://gateway.discord.gg/?encoding=json&v=10"),
                timeout=10
            )
            hello = await asyncio.wait_for(ws.receive_json(), 10)
            hi = hello["d"]["heartbeat_interval"] / 1000

            # Load guild/channel
            import configparser as cp
            cfg = cp.ConfigParser(interpolation=None, delimiters=("=",),
                                   comment_prefixes=("#", ";"),
                                   inline_comment_prefixes=("#", ";"))
            cfg.optionxform = str
            settings = "/home/zhoel/workspace/dpi-tester/settings.ini"
            cfg.read(settings, encoding="utf-8")
            guild_id = cfg.get("discord", "guild_id", fallback="")
            channel_id = cfg.get("discord", "channel_id", fallback="")

            async def hb():
                while True:
                    await asyncio.sleep(hi)
                    try: await ws.send_json({"op": 1, "d": None})
                    except: break
            hbt = asyncio.create_task(hb())

            await ws.send_json({"op": 2, "d": {
                "token": token,
                "properties": {"os": "linux", "browser": "chrome", "device": "pc"},
                "intents": 513
            }})

            # Join voice channel
            if guild_id and channel_id:
                await ws.send_json({"op": 4, "d": {
                    "guild_id": guild_id,
                    "channel_id": channel_id,
                    "self_mute": True, "self_deaf": True
                }})

            voice_endpoint = ""
            voice_token_shard = ""
            user_id = ""
            session_id = ""
            t0 = asyncio.get_event_loop().time()

            while True:
                try:
                    msg = await asyncio.wait_for(ws.receive_json(), 15)
                except asyncio.TimeoutError:
                    break

                t = msg.get("t", "")
                d = msg.get("d", {})

                if t == "READY":
                    user_id = d["user"]["id"]

                if t == "VOICE_STATE_UPDATE":
                    session_id = d.get("session_id", "")

                if t == "VOICE_SERVER_UPDATE":
                    voice_endpoint = d["endpoint"]
                    voice_token_shard = d["token"]
                    break

                if asyncio.get_event_loop().time() - t0 > 25:
                    break

            hbt.cancel()
            await ws.close()

            # ── Voice WS → OP2 Ready ──
            if not voice_endpoint or not voice_token_shard:
                await session.close()
                return None

            parts = voice_endpoint.rsplit(":", 1)
            v_host = parts[0]
            v_port = int(parts[1]) if len(parts) > 1 else 443

            vws = await asyncio.wait_for(
                session.ws_connect(f"wss://{v_host}:{v_port}"),
                timeout=10
            )
            await asyncio.wait_for(vws.receive_json(), 10)

            await vws.send_json({"op": 0, "d": {
                "server_id": guild_id,
                "user_id": user_id,
                "session_id": session_id,
                "token": voice_token_shard,
            }})

            result = {}
            v_t0 = asyncio.get_event_loop().time()
            while True:
                vmsg = await asyncio.wait_for(vws.receive_json(), 10)
                vop = vmsg["op"]
                vd = vmsg.get("d", {})
                if vop == 2:
                    ip_addr = vd.get("ip", "")
                    udp_port = vd.get("port", 0)
                    ssrc = vd.get("ssrc", 1)
                    result = {
                        "ip": ip_addr,
                        "port": udp_port,
                        "ssrc": ssrc,
                        "voice_ws_endpoint": voice_endpoint,
                    }
                    break
                if vop == 9:  # Invalid session — retry without session_id
                    await vws.send_json({"op": 0, "d": {
                        "server_id": guild_id,
                        "user_id": user_id,
                        "session_id": "",
                        "token": voice_token_shard,
                    }})
                if asyncio.get_event_loop().time() - v_t0 > 15:
                    break

            await vws.close()
            await session.close()

            if result:
                print(f"[discovery] Voice server: {result['ip']}:{result['port']} "
                      f"(SSRC={result['ssrc']})")
            return result if result else None

        finally:
            await session.close()
    except Exception as e:
        print(f"[discovery] Failed: {e}")
        return None
    finally:
        _manage_singbox(False)
        print("[discovery] sing-box stopped")
