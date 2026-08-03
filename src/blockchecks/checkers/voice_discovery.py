"""Voice endpoint auto-discovery via sing-box SOCKS5 proxy.

Flow (with token):
  1. Start sing-box proxy
  2. Gateway WS → VOICE_SERVER_UPDATE → endpoint
  3. Voice WS → OP0 Identify → OP2 Ready → IP + UDP port + SSRC
  4. Stop sing-box

Flow (without token):
  Returns None → caller uses static IP fallback.
"""

import asyncio
import os
import subprocess
import threading
import time

from blockchecks.checkers.voice_dns import discover_voice_endpoints as dns_discover
from blockchecks.engine.config import (
    DPI_TESTER_SETTINGS,
    SING_BOX_BIN,
    SING_BOX_CONFIG,
    SOCKS5_PROXY,
)

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


def load_token() -> str | None:
    settings = DPI_TESTER_SETTINGS
    if not os.path.exists(settings):
        return None
    try:
        mode = os.stat(settings).st_mode
    except OSError:
        return None
    if mode & 0o002:
        print(
            f"[discovery] WARNING: refusing world-writable settings file: {settings}"
        )
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


def write_secure_text(path: str, content: str, *, mode: int = 0o600) -> None:
    """Write text atomically-ish with restrictive permissions (token/settings)."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, path)
        os.chmod(path, mode)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


async def discover_voice_endpoint() -> dict | None:
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
        import aiohttp
        from aiohttp_socks import ProxyConnector

        connector = ProxyConnector.from_url(SOCKS5_PROXY)
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        session = aiohttp.ClientSession(timeout=timeout, connector=connector)

        try:
            # ── Gateway WS ──
            ws = await asyncio.wait_for(
                session.ws_connect("wss://gateway.discord.gg/?encoding=json&v=10"), timeout=10
            )
            hello = await asyncio.wait_for(ws.receive_json(), 10)
            hi = hello["d"]["heartbeat_interval"] / 1000

            # Load guild/channel
            import configparser as cp

            cfg = cp.ConfigParser(
                interpolation=None,
                delimiters=("=",),
                comment_prefixes=("#", ";"),
                inline_comment_prefixes=("#", ";"),
            )
            cfg.optionxform = str
            cfg.read(DPI_TESTER_SETTINGS, encoding="utf-8")
            guild_id = cfg.get("discord", "guild_id", fallback="")
            channel_id = cfg.get("discord", "channel_id", fallback="")

            async def hb():
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

            while True:
                try:
                    msg = await asyncio.wait_for(ws.receive_json(), 15)
                except asyncio.TimeoutError:
                    break

                t = msg.get("t", "")
                d = msg.get("d", {})

                if t == "READY":
                    user_id = d["user"]["id"]
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

                if t == "VOICE_STATE_UPDATE":
                    session_id = d.get("session_id", "")
                    if session_id:
                        got_session = True

                if t == "VOICE_SERVER_UPDATE":
                    voice_endpoint = d["endpoint"]
                    voice_token_shard = d["token"]
                    got_server = True

                # Wait for BOTH events before breaking
                if got_session and got_server:
                    break

                if asyncio.get_event_loop().time() - t0 > 25:
                    break

            hbt.cancel()
            await ws.close()

            if not voice_endpoint or not voice_token_shard:
                await session.close()
                return None

            # ── Voice WS → OP2 Ready ──
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

            result = {}
            op9_retries = 0
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
                if vop == 9 and op9_retries < 2:
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
                    continue
                if vop == 9:
                    break
                if asyncio.get_event_loop().time() - v_t0 > 15:
                    break

            await vws.close()
            await session.close()

            if result:
                print(
                    f"[discovery] Voice server: {result['ip']}:{result['port']} "
                    f"(SSRC={result['ssrc']})"
                )
            return result if result else None

        finally:
            await session.close()
    except Exception as e:
        print(f"[discovery] Failed: {e}")
        return None
    finally:
        _manage_singbox(False)
        print("[discovery] sing-box stopped")


async def discover_multiple(
    count: int = 5, use_dns: bool = True, use_cache: bool = True
) -> list[dict]:
    """Discover N Discord voice UDP endpoints.

    Layer 1 (DNS): finland{N}.discord.gg bulk resolution (no auth needed)
    Layer 2 (Gateway): WS → OP2 Ready (needs token)
    Layer 3 (Cache): previously discovered endpoints

    Returns: [{"ip": str, "port": int, "hostname": str}, ...]
    """
    endpoints = []
    seen_ips: set[str] = set()

    # ── Layer 1: DNS bulk ──
    if use_dns:
        try:
            dns_eps = await dns_discover(count, use_cache=use_cache)
            for ep in dns_eps:
                ip = ep.get("ip", "")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    endpoints.append(ep)
        except Exception as e:
            print(f"[discovery] DNS layer failed: {e}")

    if len(endpoints) >= count:
        return endpoints[:count]

    # ── Layer 2: Gateway (token required) ──
    token = load_token()
    if token and len(endpoints) < count:
        print(f"[discovery] Gateway layer (up to {count - len(endpoints)} more)...")
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
                print(f"[discovery] Gateway attempt failed: {e}")
                break

    return endpoints[:count]
