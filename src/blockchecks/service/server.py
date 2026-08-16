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

    # ── envelope ──

    @staticmethod
    def _envelope(resp: dict) -> dict:
        """Hybrid envelope: keep legacy ``status``/``results`` (back-compat with
        test_probe_service, HTTP bridge, gp-control-plane) and add ``ok``/``data``/``error``."""
        status = resp.get("status")
        ok = status == "ok"
        error = None if ok else resp.get("error") or (None if status == "busy" else f"cmd failed: {status}")
        data = {k: v for k, v in resp.items() if k not in ("status", "error", "ok", "data")}
        return {"ok": ok, "data": data, "error": error, **resp}

    # ── request handlers ──

    async def handle_request(self, req: dict) -> dict:
        cmd = req.get("cmd") or req.get("action")
        if cmd == "probe":
            return self._envelope(await self._handle_probe(req))
        if cmd == "status":
            return self._envelope(await self._handle_status())
        if cmd == "triage":
            return await self._handle_triage(req)
        if cmd == "find_strategy":
            return await self._handle_find_strategy(req)
        if cmd == "generate_config":
            return await self._handle_generate_config(req)
        if cmd == "dbg_probe":
            return self._envelope(await self._handle_dbg_probe(req))
        if cmd == "dbg_inspect_lua":
            return await self._handle_dbg_inspect_lua(req)
        if cmd == "dbg_dump_pool":
            return await self._handle_dbg_dump_pool()
        if cmd == "get_telemetry":
            return self._envelope(await self._handle_get_telemetry())
        if cmd == "stop":
            self._stop.set()
            return self._envelope({"status": "stopping"})
        return self._envelope({"status": "error", "error": f"unknown cmd: {cmd}"})

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

    # ── extended actions (MCP) ──

    async def _handle_triage(self, req: dict) -> dict:
        domain = str(req.get("domain") or "").strip()
        if not domain:
            return self._envelope({"status": "error", "error": "triage requires 'domain'"})
        try:
            from blockchecks.engine.fail_phase import FailPhase
            from blockchecks.engine.family_needs import map_triage_to_generators
            from blockchecks.engine.preflight import PreflightOptions, run_preflight_async

            report = await run_preflight_async([domain], PreflightOptions())
            t = report.triage
            data = {
                "domain": domain,
                "l3_status": (t.l3_phase.value if t and t.l3_phase else "unknown"),
                "fail_phase": (t.handshake_phase.value if t and t.handshake_phase and t.handshake_phase != FailPhase.PASS else "pass"),
                "client_hello_len": t.client_hello_len if t else 0,
                "quic_blocked": bool(t and t.quic_drop),
                "dns_tampered": bool(t and (t.dns_hijacked or t.dns_sinkhole)),
                "recommended_generators": map_triage_to_generators(t) if t else ["standard_fast"],
                "unbypassable_l3": bool(t and t.unbypassable_l3),
                "stall_phase": (t.stall_phase.value if t and t.stall_phase else None),
                "rst_at_sni": bool(t and t.rst_at_sni),
                "udp_blocked": bool(t and t.udp_blocked),
            }
            return self._envelope({"status": "ok", "results": data, **data})
        except Exception as err:
            return self._envelope({"status": "error", "error": f"triage failed: {err}"})

    async def _handle_find_strategy(self, req: dict) -> dict:
        domain = str(req.get("domain") or "").strip()
        if not domain:
            return self._envelope({"status": "error", "error": "find_strategy requires 'domain'"})
        profile = str(req.get("profile") or "fast")
        time_limit = max(5.0, min(float(req.get("time_limit_sec") or 30.0), 60.0))
        preset = "flowseal-fast" if profile == "fast" else "shortlist-tls12"
        if self.service.busy():
            return self._envelope(
                {"status": "busy", "active_run": self.service.busy(), "results": []}
            )
        try:
            from blockchecks.engine.adaptive_runner import (
                build_adaptive_queue,
                run_adaptive_tcp_bridge,
            )
            from blockchecks.engine.generators.base import StrategyItem
            from blockchecks.engine.preset_paths import resolve_strategy_preset

            path = resolve_strategy_preset(preset)
            strategies = [
                line.strip()
                for line in path.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            ]
            items = [StrategyItem(label=f"{domain}|{s}"[:60], strategy=s, protocol="tls12") for s in strategies[:120]]
            if not self.service.started:
                await self.service.start()
            queue, _ = await build_adaptive_queue(items, [domain], db=None, epsilon=0.1, load_weights=False)
            stop = asyncio.Event()

            async def _tick():
                await asyncio.sleep(time_limit)
                stop.set()

            runner = self.service.runner
            tick = asyncio.create_task(_tick())
            try:
                result = await asyncio.wait_for(
                    run_adaptive_tcp_bridge(
                        runner,
                        queue,
                        timeout=float(req.get("timeout") or 3.0),
                        bridge_batch=self.service.bridge_batch,
                        stop_event=stop,
                        workers=int(getattr(runner, "pool_size", 4) or 4),
                    ),
                    timeout=time_limit + 2.0,
                )
            except asyncio.TimeoutError:
                stop.set()
                await asyncio.sleep(0.2)
                result = None
            finally:
                tick.cancel()
            data = {
                "domain": domain,
                "profile": profile,
                "time_limit_sec": time_limit,
                "top_strategies": [],
                "done": 0,
                "passed": 0,
                "timed_out": False,
            }
            if result is None:
                data["timed_out"] = True
            elif result.metrics is not None:
                data["done"] = result.metrics.jobs_run
                data["passed"] = result.metrics.jobs_passed
                data["time_to_first_pass_s"] = result.metrics.time_to_first_pass
            return self._envelope({"status": "ok", "results": data, **data})
        except Exception as err:
            return self._envelope({"status": "error", "error": f"find_strategy failed: {err}"})

    async def _handle_generate_config(self, req: dict) -> dict:
        target_os = str(req.get("target_os") or "linux").lower()
        domains = [d for d in (req.get("domains") or []) if isinstance(d, str)]
        if target_os not in ("keenetic", "openwrt", "linux"):
            return self._envelope(
                {"status": "error", "error": f"unsupported target_os: {target_os}"}
            )
        try:
            from blockchecks.engine.conf_builder import build_keenetic_conf, build_raw_conf

            # Best-known-pass strategies fallback (offline, no daemon scan).
            tcp = ["fake:blob=stun:repeats=6:tcp_ts=-1000"]
            udp = ["fake:blob=discord_udp:repeats=6"]
            if target_os == "keenetic":
                content = build_keenetic_conf(
                    tcp_strategies=tcp, udp_strategies=udp, domains=domains
                )
            else:
                content = build_raw_conf(tcp_strategies=tcp, udp_strategies=udp, domains=domains)
            data = {"config_content": content, "target_os": target_os, "domains": domains}
            return self._envelope({"status": "ok", "results": data, **data})
        except Exception as err:
            return self._envelope({"status": "error", "error": f"generate_config failed: {err}"})

    async def _handle_dbg_probe(self, req: dict) -> dict:
        dry = bool(req.get("dry_run_db", True))
        if not dry:
            req["dry_run_db"] = False
        # ProbeService.runner runs without a db (serve creates no store), so
        # debug probes never write to production state.db. Guard for safety.
        return await self._handle_probe(req)

    async def _handle_dbg_inspect_lua(self, req: dict) -> dict:
        domain = str(req.get("domain") or "").strip()
        strategy = str(req.get("strategy") or "").strip()
        if not domain or not strategy:
            return self._envelope(
                {"status": "error", "error": "dbg_inspect_lua requires 'domain' and 'strategy'"}
            )
        try:
            from blockchecks.service.lua_bridge_ipc import LuaBridge

            bridge = LuaBridge("bs-mcp-dbg")
            bridge.setup()
            try:
                events = bridge.drain_events()
            finally:
                bridge.teardown()
            data = {
                "domain": domain,
                "strategy": strategy,
                "events": [e.to_dict() if hasattr(e, "to_dict") else vars(e) for e in events],
                "desync_applied": any(getattr(e, "event", "") == "APPLIED" for e in events),
                "rst_in_detected": any(
                    getattr(e, "event", "") == "STRATEGY_FAIL" and getattr(e, "reason", "") == "rst_in"
                    for e in events
                ),
            }
            return self._envelope({"status": "ok", "results": data, **data})
        except Exception as err:
            return self._envelope({"status": "error", "error": f"dbg_inspect_lua failed: {err}"})

    async def _handle_dbg_dump_pool(self) -> dict:
        try:
            from blockchecks.engine.paths import RUN_LOCK_FILE
            from blockchecks.engine.preflight import find_host_nfqws2_pids

            ns_names: list[str] = []
            if self.service.runner is not None and self.service.runner.pool is not None:
                ns_names = list(getattr(self.service.runner.pool, "_names", []) or [])
            data = {
                "netns_pool": ns_names,
                "pool_size": self.service.pool_size,
                "started": self.service.started,
                "nfqws2_pids": find_host_nfqws2_pids(),
                "run_lock_present": RUN_LOCK_FILE.exists(),
                "active_run": self.service.busy(),
            }
            return self._envelope({"status": "ok", "results": data, **data})
        except Exception as err:
            return self._envelope({"status": "error", "error": f"dbg_dump_pool failed: {err}"})

    async def _handle_get_telemetry(self) -> dict:
        try:
            from blockchecks.engine.paths import RUN_LOCK_FILE

            active = self.service.busy()
            data = {
                "status": "ok",
                "active_run": active,
                "pool_size": self.service.pool_size,
                "started": self.service.started,
                "uptime_s": round(self.service.uptime, 1) if self.service.started else 0.0,
                "run_lock_present": RUN_LOCK_FILE.exists(),
            }
            return {"status": "ok", "results": data, **data}
        except Exception as err:
            return self._envelope({"status": "error", "error": f"get_telemetry failed: {err}"})

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
