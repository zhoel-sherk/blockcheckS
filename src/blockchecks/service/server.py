"""Unix-socket JSON API plus optional Bearer HTTP/SSE. Both call handle_request."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
from pathlib import Path
from typing import Any

from blockchecks.engine.paths import STATE_DIR
from blockchecks.service.probe_service import ProbeRequest, ProbeService

log = logging.getLogger(__name__)


SOCKET_PATH = STATE_DIR / "blockchecks.sock"

SSE_HEARTBEAT_SECONDS = 15.0
HTTP_HEADER_READ_TIMEOUT = 30.0


def _triage_fail_phase(t) -> str:
    from blockchecks.engine.fail_phase import FailPhase

    skip = {FailPhase.UNKNOWN, FailPhase.PASS, None}
    for phase in (
        getattr(t, "handshake_phase", None),
        getattr(t, "stall_phase", None),
        getattr(t, "l3_phase", None),
    ):
        if phase not in skip:
            return phase.value
    return "pass"


async def _top_from_store(store: Any, domain: str) -> list[dict[str, Any]]:
    if store is None:
        return []
    try:
        details = await store.get_working_tcp_details(domain)
    except Exception:
        return []
    return _merge_top_strategies(
        [
            {
                "strategy": d.get("name") or d.get("strategy") or "",
                "success": True,
                "http_code": d.get("http_code"),
                "latency_ms": float(d.get("latency_ms") or 0.0),
                "bytes_read": 0,
                "fail_phase": None,
                "rst_in_ttl": None,
            }
            for d in details
        ]
    )


def _tcp_pass_row(r: Any) -> dict[str, Any]:
    item = getattr(r, "item", None)
    return {
        "strategy": getattr(item, "strategy", None) or getattr(r, "strategy", "") or "",
        "success": True,
        "http_code": getattr(r, "http_code", None),
        "latency_ms": float(getattr(r, "latency_ms", 0.0) or 0.0),
        "bytes_read": int(getattr(r, "content_length", 0) or getattr(r, "bytes_read", 0) or 0),
        "fail_phase": getattr(r, "fail_phase", None) or None,
        "rst_in_ttl": getattr(r, "rst_in_ttl", None),
    }


def _merge_top_strategies(rows: list[dict[str, Any]], *, limit: int = 20) -> list[dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = str(row.get("strategy") or "")
        if not key:
            continue
        prev = best.get(key)
        if prev is None or (row.get("http_code") and not prev.get("http_code")):
            best[key] = row
            continue
        if float(row.get("latency_ms") or 0) < float(prev.get("latency_ms") or 0):
            best[key] = row
    return sorted(best.values(), key=lambda r: float(r.get("latency_ms") or 0))[:limit]


def _tap_runner_passes(runner: Any, sink: list[dict[str, Any]]):
    """Record PASS probe results from runner methods; return a restore callable."""
    orig_tcp = runner.test_tcp
    orig_batch = getattr(runner, "_run_probe_batch", None)
    orig_domains = getattr(runner, "test_tcp_domains", None)

    async def test_tcp(*a, **k):
        r = await orig_tcp(*a, **k)
        if getattr(r, "success", False):
            sink.append(_tcp_pass_row(r))
        return r

    runner.test_tcp = test_tcp
    if orig_batch is not None:

        async def _run_probe_batch(*a, **k):
            results = await orig_batch(*a, **k)
            sink.extend(_tcp_pass_row(r) for r in results if getattr(r, "success", False))
            return results

        runner._run_probe_batch = _run_probe_batch
    if orig_domains is not None:

        async def test_tcp_domains(*a, **k):
            results = await orig_domains(*a, **k)
            sink.extend(_tcp_pass_row(r) for r in results if getattr(r, "success", False))
            return results

        runner.test_tcp_domains = test_tcp_domains

    def restore() -> None:
        runner.test_tcp = orig_tcp
        if orig_batch is not None:
            runner._run_probe_batch = orig_batch
        if orig_domains is not None:
            runner.test_tcp_domains = orig_domains

    return restore


def _tap_queue_passes(queue: Any, sink: list[dict[str, Any]]):
    orig = queue.mark_done

    def mark_done(job, *, passed: bool = False, **k):
        if passed:
            item = getattr(job, "item", None)
            sink.append(
                {
                    "strategy": getattr(item, "strategy", "") if item is not None else "",
                    "success": True,
                    "http_code": None,
                    "latency_ms": 0.0,
                    "bytes_read": 0,
                    "fail_phase": None,
                    "rst_in_ttl": None,
                }
            )
        return orig(job, passed=passed, **k)

    queue.mark_done = mark_done
    return lambda: setattr(queue, "mark_done", orig)


def _authorization_token(authorization: str | None) -> str | None:
    """Parse ``Authorization: Bearer <token>`` -> token or None."""
    if not isinstance(authorization, str):
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


class ProbeServer:
    """Unix-socket JSON line server over ProbeService.

    Also owns an in-process event bus for SSE: callers can subscribe with
    ``subscribe_events()`` and receive dict events published via
    ``publish_event()`` (probe results, triage/find-strategy progress).
    """

    def __init__(self, service: ProbeService, socket_path: str | Path | None = None):
        self.service = service
        self.socket_path = Path(socket_path or SOCKET_PATH)
        self._server: asyncio.AbstractServer | None = None
        self._http: asyncio.AbstractServer | None = None
        self._stop = asyncio.Event()
        self._event_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    # envelope

    @staticmethod
    def _envelope(resp: dict) -> dict:
        """JSON envelope: ``status``/``results`` plus ``ok``/``data``/``error``."""
        status = resp.get("status")
        ok = status == "ok"
        error = (
            None
            if ok
            else resp.get("error") or (None if status == "busy" else f"cmd failed: {status}")
        )
        data = {k: v for k, v in resp.items() if k not in ("status", "error", "ok", "data")}
        return {"ok": ok, "data": data, "error": error, **resp}

    # request handlers

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
        if cmd == "set_debug":
            return self._envelope(self._handle_set_debug(req))
        if cmd == "log_tail":
            return self._envelope(self._handle_log_tail(req))
        if cmd == "results":
            return self._envelope(await self._handle_results(req))
        if cmd == "stop":
            return self._envelope(await self._handle_stop())
        return self._envelope({"status": "error", "error": f"unknown cmd: {cmd}"})

    async def _handle_stop(self) -> dict:
        self._stop.set()
        return {"status": "ok", "action_status": "stopping"}

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
            timeout=float(req.get("timeout") or self.service.default_timeout),
            repeats=int(req.get("repeats") or 1),
        )
        self.publish_event({"type": "probe_start", "domains": domains, "strategies": strategies})
        resp = await self.service.probe(r)
        for result in resp.get("results") or []:
            if isinstance(result, dict):
                self.publish_event({"type": "probe_result", **result})
        self.publish_event({"type": "probe_done", "count": len(resp.get("results") or [])})
        return resp

    async def _handle_status(self) -> dict:
        campaign = self.service.busy()
        return {
            "status": "busy" if campaign else "ok",
            "active_run": campaign,
            "pool_size": self.service.pool_size,
            "started": self.service.started,
            "uptime_s": round(self.service.uptime, 1) if self.service.started else 0.0,
        }

    # extended actions (MCP)

    async def _handle_triage(self, req: dict) -> dict:
        domain = str(req.get("domain") or "").strip()
        if not domain:
            return self._envelope({"status": "error", "error": "triage requires 'domain'"})
        try:
            from blockchecks.engine.family_needs import map_triage_to_generators
            from blockchecks.engine.family_registry import DEFAULT_FAMILIES
            from blockchecks.engine.generators.base import StrategyItem
            from blockchecks.engine.preflight import PreflightOptions, run_preflight_async

            opts = PreflightOptions(skip_diagnostics=False)
            runner = self.service.runner if self.service.started else None
            if runner is not None:

                async def probe(strategy: str) -> tuple[bool, str, int]:
                    item = StrategyItem(label="preflight_diag", strategy=strategy)
                    async with self.service._lock:
                        r = await runner.test_tcp(item, domain, timeout=min(opts.timeout, 5.0))
                    return bool(r.success), r.error or "", int(r.http_code or 0)

                opts.fooling_probe_fn = probe
            async with self.service._lock:
                report = await run_preflight_async([domain], opts)
            t = report.triage
            data = {
                "domain": domain,
                "l3_status": (t.l3_phase.value if t and t.l3_phase else "unknown"),
                "fail_phase": _triage_fail_phase(t),
                "client_hello_len": t.client_hello_len if t else 0,
                "quic_blocked": bool(t and t.quic_drop),
                "dns_tampered": bool(t and (t.dns_hijacked or t.dns_sinkhole)),
                "recommended_generators": map_triage_to_generators(t)
                if t
                else list(DEFAULT_FAMILIES),
                "unbypassable_l3": bool(t and t.unbypassable_l3),
                "stall_phase": (t.stall_phase.value if t and t.stall_phase else None),
                "rst_at_sni": bool(t and t.rst_at_sni),
                "udp_blocked": bool(t and t.udp_blocked),
                "voice_ok": bool(t and t.voice_ok),
                "viable_foolings": list(t.viable_foolings) if t else [],
                "viable_blobs": list(t.viable_blobs) if t else [],
                "split_mode": t.split_mode if t else "",
                "server_hops": t.server_hops if t else None,
                "dpi_hops": t.dpi_hops if t else None,
                "autottl_delta": t.autottl_delta if t else None,
                "ech_blocked": t.ech_blocked if t else None,
                "http_blocked": t.http_blocked if t else None,
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
            items = [
                StrategyItem(label=f"{domain}|{s}"[:60], strategy=s, protocol="tls12")
                for s in strategies[:120]
            ]
            if not self.service.started:
                await self.service.start()
            queue, _ = await build_adaptive_queue(
                items, [domain], db=None, epsilon=0.1, load_weights=False
            )
            stop = asyncio.Event()

            async def _tick():
                await asyncio.sleep(time_limit)
                stop.set()

            runner = self.service.runner
            tick = asyncio.create_task(_tick())
            sink: list[dict[str, Any]] = []
            restore_runner = (
                _tap_runner_passes(runner, sink) if runner is not None else lambda: None
            )
            restore_queue = _tap_queue_passes(queue, sink)
            try:
                async with self.service._lock:
                    result = await asyncio.wait_for(
                        run_adaptive_tcp_bridge(
                            runner,
                            queue,
                            timeout=float(req.get("timeout") or 3.0),
                            bridge_batch=self.service.bridge_batch,
                            stop_event=stop,
                            workers=max(1, int(self.service.pool_size)),
                        ),
                        timeout=time_limit + 2.0,
                    )
            except asyncio.TimeoutError:
                stop.set()
                await asyncio.sleep(0.2)
                result = None
            finally:
                restore_queue()
                restore_runner()
                tick.cancel()
            top = _merge_top_strategies(sink)
            if not top:
                top = await _top_from_store(self.service.db, domain)
            data = {
                "domain": domain,
                "profile": profile,
                "time_limit_sec": time_limit,
                "top_strategies": top,
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
        # MCP client sends singular domain/strategy/fake_blob; map to the
        # batch probe contract (domains[]/strategies[]).
        domain = str(req.get("domain") or "").strip()
        strategy = str(req.get("strategy") or "").strip()
        if domain and not req.get("domains"):
            req["domains"] = [domain]
        if strategy and not req.get("strategies"):
            req["strategies"] = [strategy]
        # fake_blob is injected into the strategy string when supplied.
        blob = str(req.get("fake_blob") or "").strip()
        if blob:
            req["strategies"] = [
                s if "blob=" in s else f"fake:blob={blob}" for s in (req.get("strategies") or [])
            ]
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
                    getattr(e, "event", "") == "STRATEGY_FAIL"
                    and getattr(e, "reason", "") == "rst_in"
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
            from blockchecks.engine.log import debug_status

            data["debug"] = debug_status()
            return {"status": "ok", "results": data, **data}
        except Exception as err:
            return self._envelope({"status": "error", "error": f"get_telemetry failed: {err}"})

    @staticmethod
    def _as_bool(val: Any, default: bool = False) -> bool:
        if val is None:
            return default
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _as_int(val: Any, default: int) -> int:
        try:
            return int(val)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _handle_set_debug(req: dict) -> dict:
        from blockchecks.engine.log import set_debug_mode

        enabled = ProbeServer._as_bool(req.get("enabled"), True)
        data = set_debug_mode(enabled)
        return {"status": "ok", "results": data, **data}

    @staticmethod
    def _handle_log_tail(req: dict) -> dict:
        from blockchecks.engine.log import log_tail

        source = str(req.get("source") or "python")
        tail = ProbeServer._as_int(req.get("tail"), 200)
        offset = ProbeServer._as_int(req.get("offset"), 0)
        raw = ProbeServer._as_bool(req.get("raw"))
        strip = not ProbeServer._as_bool(req.get("ansi"))
        data = log_tail(source, tail=tail, offset=offset, strip_ansi=strip, raw=raw)
        if not data.get("ok"):
            return {"status": "error", "error": data.get("error") or "log_tail failed", **data}
        return {"status": "ok", "results": data, **data}

    async def _handle_results(self, req: dict) -> dict:
        """Return best PASS strategies from a run database (on-the-fly).

        Resolves the DB path automatically: explicit ``?db=`` param > the
        active run.lock's db_path > the default state.db. Reads are read-only
        and never write to the campaign DB.
        """
        try:
            from blockchecks.engine.paths import DEFAULT_DB_PATH
            from blockchecks.engine.store import open_run_store
            from blockchecks.service.run_control import read_active_run

            db_path = str(req.get("db") or "").strip()
            if not db_path:
                active = read_active_run()
                if active is not None and active.db_path:
                    db_path = str(active.db_path)
            if not db_path:
                db_path = str(DEFAULT_DB_PATH)

            limit = int(req.get("limit") or 5)
            limit = max(1, min(limit, 50))
            domains = [d for d in (req.get("domains") or []) if isinstance(d, str)]

            store = open_run_store(db_path)
            try:
                if domains:
                    tcp = await store.get_common_tcp(domains, limit=limit)
                else:
                    tcp = await store.get_best_by_coverage(limit=limit)
                udp = await store.get_best_udp(limit=limit)
                quic = await store.get_best_quic("", limit=limit)
            finally:
                await store.close()

            data = {
                "status": "ok",
                "db": db_path,
                "limit": limit,
                "tcp": tcp,
                "udp": udp,
                "quic": quic,
            }
            return self._envelope({"status": "ok", "results": data, **data})
        except Exception as err:
            return self._envelope({"status": "error", "error": f"results failed: {err}"})

    # event bus (SSE)

    def publish_event(self, event: dict[str, Any]) -> None:
        """Fan out an event dict to all SSE subscribers (non-blocking)."""
        for queue in list(self._event_subscribers):
            if queue.full():
                # Drop oldest event on a stalled subscriber rather than blocking.
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    def subscribe_events(self, maxsize: int = 256) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=maxsize)
        self._event_subscribers.add(queue)
        return queue

    def unsubscribe_events(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._event_subscribers.discard(queue)

    async def _stream_events(self, writer: asyncio.StreamWriter) -> None:
        """Write SSE frames until the client disconnects or the server stops."""
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/event-stream\r\n"
            b"Cache-Control: no-cache\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n"
        )
        await writer.drain()

        queue = self.subscribe_events()
        last_heartbeat = time.monotonic()
        try:
            while not self._stop.is_set():
                timeout = max(0.5, last_heartbeat + SSE_HEARTBEAT_SECONDS - time.monotonic())
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=timeout)
                except asyncio.TimeoutError:
                    try:
                        writer.write(b": heartbeat\n\n")
                        await writer.drain()
                    except (ConnectionError, OSError):
                        break
                    last_heartbeat = time.monotonic()
                    continue
                event_type = str(event.get("type") or "event")
                payload = json.dumps(event, separators=(",", ":")).encode("utf-8")
                try:
                    writer.write(f"event: {event_type}\n".encode())
                    writer.write(b"data: ")
                    writer.write(payload)
                    writer.write(b"\n\n")
                    await writer.drain()
                except (ConnectionError, OSError):
                    break
        finally:
            self.unsubscribe_events(queue)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    # socket lifecycle

    async def serve(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self.socket_path.unlink(missing_ok=True)
        self._server = await asyncio.start_unix_server(self._client, str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        # When launched via sudo, reclaim ownership so user-space MCP/CLI
        # clients (running as SUDO_UID) can connect to the socket.
        from blockchecks.engine.paths import reclaim_sudo_ownership

        reclaim_sudo_ownership(self.socket_path)
        log.info("%s", f"  [serve] listening on {self.socket_path}")
        loop = asyncio.get_running_loop()

        def _on_usr1() -> None:
            from blockchecks.engine.log import toggle_debug_mode

            toggle_debug_mode()

        try:
            loop.add_signal_handler(signal.SIGUSR1, _on_usr1)
        except (NotImplementedError, RuntimeError):
            pass
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

    @staticmethod
    async def _read_http_request(
        reader: asyncio.StreamReader,
    ) -> tuple[str, str, str | None, bytes] | None:
        """Read one HTTP request -> (method, path, authorization, body) or None."""
        request_line = await asyncio.wait_for(reader.readline(), timeout=HTTP_HEADER_READ_TIMEOUT)
        if not request_line:
            return None
        parts = request_line.decode("utf-8", "replace").strip().split(" ", 2)
        if len(parts) != 3:
            return None
        method, path, _ = parts
        authorization: str | None = None
        content_length = 0
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            low = line.decode("utf-8", "replace").lower()
            if low.startswith("authorization:"):
                authorization = line.decode("utf-8", "replace").split(":", 1)[1].strip()
            elif low.startswith("content-length:"):
                try:
                    content_length = int(low.split(":", 1)[1].strip())
                except ValueError:
                    content_length = 0
        body = b""
        if content_length > 0:
            body = await asyncio.wait_for(
                reader.readexactly(content_length), timeout=HTTP_HEADER_READ_TIMEOUT
            )
        return method, path, authorization, body

    @staticmethod
    def _parse_http_body(body: bytes) -> dict | None:
        try:
            parsed = json.loads(body.decode("utf-8")) if body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    @staticmethod
    def _parse_query_params(path: str) -> dict[str, Any]:
        """Parse ``?a=1&b=2`` from a request path into a dict."""
        from urllib.parse import parse_qs, urlparse

        query = parse_qs(urlparse(path).query)
        return {k: v[0] for k, v in query.items()}

    @staticmethod
    def _busy_status_code(resp: dict) -> int:
        return 423 if resp.get("status") == "busy" else 200

    async def _route_http_request(
        self,
        method: str,
        path: str,
        body: bytes,
    ) -> tuple[dict, int] | None:
        """Route one authenticated HTTP request.

        Returns ``(response, status_code)`` or ``None`` when the handler takes
        over the connection (SSE stream).
        """
        if path == "/api/events" and method in {"GET", "HEAD"}:
            return None
        if path == "/api/status" and method in {"GET", "HEAD"}:
            resp = self._envelope(await self._handle_status())
            return resp, self._busy_status_code(resp)
        if path == "/api/telemetry" and method in {"GET", "HEAD"}:
            return self._envelope(await self._handle_get_telemetry()), 200
        if (path == "/api/logs" or path.startswith("/api/logs?")) and method in {
            "GET",
            "HEAD",
        }:
            req = self._parse_query_params(path)
            return self._envelope(self._handle_log_tail(req)), 200
        if path == "/api/results" or path.startswith("/api/results?"):
            req = self._parse_query_params(path)
            return self._envelope(await self._handle_results(req)), 200
        if path == "/api/stop" and method == "POST":
            return self._envelope(await self._handle_stop()), 200
        action_paths = {
            "/api/probe": "probe",
            "/api/triage": "triage",
            "/api/find-strategy": "find_strategy",
            "/api/generate-config": "generate_config",
            "/api/dbg-probe": "dbg_probe",
            "/api/set-debug": "set_debug",
        }
        if path in action_paths and method == "POST":
            req = self._parse_http_body(body)
            if req is None:
                return {"status": "error", "error": "bad json body"}, 400
            req.setdefault("cmd", action_paths[path])
            resp = await self.handle_request(req)
            return resp, self._busy_status_code(resp)
        # Routes that still require a token.
        if method == "GET" and path.startswith("/status"):
            resp = self._envelope(await self._handle_status())
            return resp, self._busy_status_code(resp)
        if method == "POST" and path.startswith("/stop"):
            return self._envelope(await self._handle_stop()), 200
        if method == "POST" and (path.startswith("/probe") or path == "/"):
            req = self._parse_http_body(body)
            if req is None:
                return {"status": "error", "error": "bad json body"}, 400
            req.setdefault("cmd", "probe")
            resp = await self.handle_request(req)
            return resp, self._busy_status_code(resp)
        return {"status": "error", "error": "not found"}, 404

    async def serve_http(
        self,
        host: str = "127.0.0.1",
        port: int = 8089,
        token: str | None = None,
    ) -> None:
        """Authenticated HTTP bridge over the same request handlers (stdlib only).

        All routes require ``Authorization: Bearer <token>`` except ``/api/health``.
        When *token* is empty/None the HTTP bridge is disabled (no listener).
        Exposes the socket actions under ``/api/*`` plus an SSE stream at
        ``/api/events`` for on-the-fly progress.
        """
        if not token:
            log.info("  [serve] HTTP bridge disabled: no token provided")
            return

        async def _send_json(
            writer: asyncio.StreamWriter,
            resp: dict,
            status_code: int,
        ) -> None:
            payload = json.dumps(resp).encode()
            reason = {
                200: "OK",
                400: "Bad Request",
                401: "Unauthorized",
                404: "Not Found",
                423: "Locked",
            }.get(status_code, "OK")
            writer.write(
                (
                    f"HTTP/1.1 {status_code} {reason}\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
            )
            writer.write(payload)
            await writer.drain()

        async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            sse_stream = False
            try:
                request = await self._read_http_request(reader)
                if request is None:
                    return
                method, path, authorization, body = request

                # Public liveness probe — no token required.
                if method in {"GET", "HEAD"} and path == "/api/health":
                    await _send_json(writer, {"status": "ok"}, 200)
                    return

                # Everything else requires a Bearer token.
                if _authorization_token(authorization) != token:
                    await _send_json(writer, {"status": "error", "error": "unauthorized"}, 401)
                    return

                routed = await self._route_http_request(method, path, body)
                if routed is None:
                    sse_stream = True
                    await self._stream_events(writer)
                    return
                resp, status_code = routed
                await _send_json(writer, resp, status_code)
            except (asyncio.TimeoutError, ConnectionError, OSError, ValueError):
                pass
            finally:
                if not sse_stream:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (ConnectionError, OSError):
                        pass

        self._http = await asyncio.start_server(_handle, host, port)
        log.info("%s", f"  [serve] authenticated HTTP bridge on http://{host}:{port}")
        async with self._http:
            await self._stop.wait()
