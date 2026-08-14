"""blockcheckS probe server — Unix socket core + thin HTTP bridge.

Core is strictly ``asyncio.start_unix_server`` (no deps). Clients send a
single-line JSON request (``{"cmd": "probe"|"status"|"stop", ...}``) and get a
single-line JSON response. A lightweight HTTP layer can sit in front of the
socket (or call the same ``handle_request`` directly).
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from blockchecks.engine.paths import STATE_DIR
from blockchecks.service.probe_service import ProbeRequest, ProbeService

SOCKET_PATH = STATE_DIR / "blockchecks.sock"


class ProbeServer:
    """Unix-socket JSON line server over ProbeService."""

    def __init__(self, service: ProbeService, socket_path: str | Path | None = None):
        self.service = service
        self.socket_path = Path(socket_path or SOCKET_PATH)
        self._server: asyncio.AbstractServer | None = None
        self._stop = asyncio.Event()

    # ── request handlers ──

    async def handle_request(self, req: dict) -> dict:
        cmd = req.get("cmd") or req.get("action")
        if cmd == "probe":
            return await self._handle_probe(req)
        if cmd == "status":
            return await self._handle_status()
        if cmd == "stop":
            self._stop.set()
            return {"status": "stopping"}
        return {"status": "error", "error": f"unknown cmd: {cmd}"}

    async def _handle_probe(self, req: dict) -> dict:
        domains = [d for d in (req.get("domains") or []) if isinstance(d, str)]
        strategies = [s for s in (req.get("strategies") or []) if isinstance(s, str)]
        if not domains or not strategies:
            return {
                "status": "error",
                "error": "probe requires domains[] and strategies[]",
            }
        r = ProbeRequest(
            domains=domains,
            strategies=strategies,
            protocol=str(req.get("protocol") or "tls12"),
            timeout=float(req.get("timeout") or 3.0),
            repeats=int(req.get("repeats") or 1),
        )
        return await self.service.probe(r)

    async def _handle_status(self) -> dict:
        campaign = self.service.busy()
        return {
            "status": "busy" if campaign else "ok",
            "active_run": campaign,
            "pool_size": self.service.pool_size,
            "started": self.service.started,
            "uptime_s": round(self.service.uptime, 1) if self.service.started else 0.0,
        }

    # ── socket lifecycle ──

    async def serve(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self.socket_path.unlink(missing_ok=True)
        self._server = await asyncio.start_unix_server(self._client, str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        print(f"  [serve] listening on {self.socket_path}")
        async with self._server:
            await self._stop.wait()

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=60)
            if not line:
                return
            try:
                req = json.loads(line.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                writer.write((json.dumps({"status": "error", "error": "bad json"}) + "\n").encode())
                await writer.drain()
                return
            resp = await self.handle_request(req)
            writer.write((json.dumps(resp) + "\n").encode("utf-8"))
            await writer.drain()
        except asyncio.TimeoutError:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


    async def serve_http(self, host: str = "127.0.0.1", port: int = 8089) -> None:
        """Thin HTTP bridge over the same request handlers (stdlib only).

        POST /probe, GET /status, POST /stop — JSON bodies. This is a minimal
        bridge so external apps (e.g. gp-control-plane) don't need a socket
        client; the probe core remains the Unix socket.
        """

        async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                request_line = await asyncio.wait_for(reader.readline(), timeout=30)
                if not request_line:
                    return
                method, path, _ = request_line.decode("utf-8", "replace").strip().split(" ", 2)
                # read headers until blank line
                content_length = 0
                while True:
                    line = await reader.readline()
                    if line in (b"\r\n", b"\n", b""):
                        break
                    low = line.decode("utf-8", "replace").lower()
                    if low.startswith("content-length:"):
                        try:
                            content_length = int(low.split(":", 1)[1].strip())
                        except ValueError:
                            content_length = 0
                body = b""
                if content_length > 0:
                    body = await reader.readexactly(content_length)

                if method == "GET" and path.startswith("/status"):
                    resp = await self._handle_status()
                elif method == "POST" and path.startswith("/stop"):
                    self._stop.set()
                    resp = {"status": "stopping"}
                elif method == "POST" and (path.startswith("/probe") or path == "/"):
                    try:
                        req = json.loads(body.decode("utf-8")) if body else {}
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        resp = {"status": "error", "error": "bad json body"}
                    else:
                        if not isinstance(req, dict):
                            resp = {"status": "error", "error": "body must be a JSON object"}
                        else:
                            req.setdefault("cmd", "probe")
                            resp = await self.handle_request(req)
                else:
                    resp = {"status": "error", "error": "not found"}
                payload = json.dumps(resp).encode("utf-8")
                status_line = "423 Locked" if resp.get("status") == "busy" else "200 OK"
                writer.write(
                    (
                        f"HTTP/1.1 {status_line}\r\n"
                        "Content-Type: application/json\r\n"
                        f"Content-Length: {len(payload)}\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode()
                )
                writer.write(payload)
                await writer.drain()
            except (asyncio.TimeoutError, ConnectionError, OSError, ValueError):
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass

        self._http = await asyncio.start_server(_handle, host, port)
        print(f"  [serve] HTTP bridge on http://{host}:{port}")
        async with self._http:
            await self._stop.wait()

    def make_service(**kwargs) -> ProbeService:
        return ProbeService(**kwargs)
