"""Unit tests for the authenticated HTTP bridge (http bridge).

These tests exercise the raw asyncio HTTP server on an ephemeral port:
authentication (401 vs 200), route dispatch (/api/* and legacy /probe),
busy -> 423, and the SSE event stream.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from blockchecks.service.probe_service import ProbeRequest, ProbeService
from blockchecks.service.server import ProbeServer

HTTP_TOKEN = "test-token-abc"


class _HttpProbe:
    """Minimal raw HTTP/1.1 client for the stdlib bridge."""

    def __init__(self, port: int, token: str | None = None):
        self.port = port
        self.token = token

    async def request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
    ) -> tuple[int, dict]:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        payload = json.dumps(body).encode("utf-8") if body is not None else b""
        headers = [
            f"{method} {path} HTTP/1.1",
            "Host: 127.0.0.1",
            "Connection: close",
        ]
        if self.token:
            headers.append(f"Authorization: Bearer {self.token}")
        if body is not None:
            headers.append(f"Content-Length: {len(payload)}")
        writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("utf-8"))
        if payload:
            writer.write(payload)
        await writer.drain()

        status_line = (await asyncio.wait_for(reader.readline(), timeout=5)).decode(
            "utf-8", "replace"
        )
        status_code = int(status_line.split(" ", 2)[1])
        body_bytes = b""
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            if line in (b"\r\n", b"\n", b""):
                break
        try:
            body_bytes = await asyncio.wait_for(reader.read(), timeout=5)
        except (ConnectionError, OSError):
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        try:
            parsed = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            parsed = {}
        return status_code, parsed


async def _start_http_server(
    monkeypatch,
    *,
    token: str | None = HTTP_TOKEN,
) -> tuple[ProbeServer, int, asyncio.Task]:
    """Start an ephemeral HTTP bridge and return (server, port, task)."""
    import blockchecks.service.probe_service as ps

    monkeypatch.setattr(ps, "read_active_run", lambda: None)
    svc = ProbeService(pool_size=2)
    server = ProbeServer(svc, socket_path="/tmp/bs_http_test.sock")

    async def _serve():
        await server.serve_http(host="127.0.0.1", port=0, token=token)

    task = asyncio.create_task(_serve())
    # Wait for the listener to come up and read the ephemeral port.
    for _ in range(100):
        if server._http is not None and server._http.sockets:
            port = server._http.sockets[0].getsockname()[1]
            return server, port, task
        await asyncio.sleep(0.01)
    raise AssertionError("HTTP server did not start")


async def _stop_http_server(server: ProbeServer, task: asyncio.Task) -> None:
    server._stop.set()
    try:
        await asyncio.wait_for(task, timeout=5)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        task.cancel()
    finally:
        await server.service.stop()


@pytest.mark.unit
def test_http_health_is_public(monkeypatch):
    async def run():
        server, port, task = await _start_http_server(monkeypatch)
        try:
            client = _HttpProbe(port, token=None)
            status_code, resp = await client.request("GET", "/api/health")
            assert status_code == 200
            assert resp.get("status") == "ok"
        finally:
            await _stop_http_server(server, task)

    asyncio.run(run())


@pytest.mark.unit
def test_http_requires_token(monkeypatch):
    async def run():
        server, port, task = await _start_http_server(monkeypatch)
        try:
            no_token = _HttpProbe(port, token=None)
            code, resp = await no_token.request("GET", "/api/status")
            assert code == 401
            assert resp.get("error") == "unauthorized"

            bad_token = _HttpProbe(port, token="wrong")
            code, resp = await bad_token.request("GET", "/api/status")
            assert code == 401

            good = _HttpProbe(port, token=HTTP_TOKEN)
            code, resp = await good.request("GET", "/api/status")
            assert code == 200
            assert resp.get("status") == "ok"
        finally:
            await _stop_http_server(server, task)

    asyncio.run(run())


@pytest.mark.unit
def test_http_telemetry_endpoint(monkeypatch):
    async def run():
        server, port, task = await _start_http_server(monkeypatch)
        try:
            client = _HttpProbe(port, token=HTTP_TOKEN)
            code, resp = await client.request("GET", "/api/telemetry")
            assert code == 200
            assert resp.get("status") == "ok"
            assert "pool_size" in resp
            assert "debug" in resp
            assert "python_level" in resp["debug"]
        finally:
            await _stop_http_server(server, task)

    asyncio.run(run())


@pytest.mark.unit
def test_http_probe_dispatches(monkeypatch):
    async def run():
        server, port, task = await _start_http_server(monkeypatch)

        async def fake_probe(req: ProbeRequest):
            return {
                "status": "ok",
                "results": [{"domain": req.domains[0], "strategy_id": "s1", "status": "PASS"}],
            }

        server.service.probe = fake_probe  # type: ignore[method-assign]
        try:
            client = _HttpProbe(port, token=HTTP_TOKEN)
            code, resp = await client.request(
                "POST",
                "/api/probe",
                {"domains": ["a.com"], "strategies": ["fake:repeats=6"]},
            )
            assert code == 200
            assert resp.get("status") == "ok"
            assert resp["results"][0]["status"] == "PASS"
        finally:
            await _stop_http_server(server, task)

    asyncio.run(run())


@pytest.mark.unit
def test_http_probe_publishes_sse_events(monkeypatch):
    async def run():
        server, port, task = await _start_http_server(monkeypatch)

        async def fake_probe(req: ProbeRequest):
            return {
                "status": "ok",
                "results": [{"domain": "a.com", "strategy_id": "s1", "status": "PASS"}],
            }

        server.service.probe = fake_probe  # type: ignore[method-assign]

        queue = server.subscribe_events()
        try:
            client = _HttpProbe(port, token=HTTP_TOKEN)
            code, resp = await client.request(
                "POST",
                "/api/probe",
                {"domains": ["a.com"], "strategies": ["fake:repeats=6"]},
            )
            assert code == 200
            event = await asyncio.wait_for(queue.get(), timeout=2)
            assert event["type"] == "probe_start"
            event = await asyncio.wait_for(queue.get(), timeout=2)
            assert event["type"] == "probe_result"
            event = await asyncio.wait_for(queue.get(), timeout=2)
            assert event["type"] == "probe_done"
        finally:
            server.unsubscribe_events(queue)
            await _stop_http_server(server, task)

    asyncio.run(run())


@pytest.mark.unit
def test_http_legacy_probe_route(monkeypatch):
    async def run():
        server, port, task = await _start_http_server(monkeypatch)

        async def fake_probe(req: ProbeRequest):
            return {"status": "ok", "results": [{"domain": "a.com", "status": "PASS"}]}

        server.service.probe = fake_probe  # type: ignore[method-assign]
        try:
            client = _HttpProbe(port, token=HTTP_TOKEN)
            code, resp = await client.request(
                "POST",
                "/probe",
                {"domains": ["a.com"], "strategies": ["fake:repeats=6"]},
            )
            assert code == 200
            assert resp.get("status") == "ok"
        finally:
            await _stop_http_server(server, task)

    asyncio.run(run())


@pytest.mark.unit
def test_http_unknown_route_returns_404(monkeypatch):
    async def run():
        server, port, task = await _start_http_server(monkeypatch)
        try:
            client = _HttpProbe(port, token=HTTP_TOKEN)
            code, resp = await client.request("GET", "/api/nope")
            assert code == 404
        finally:
            await _stop_http_server(server, task)

    asyncio.run(run())


@pytest.mark.unit
def test_http_disabled_without_token(monkeypatch):
    async def run():
        import blockchecks.service.probe_service as ps

        monkeypatch.setattr(ps, "read_active_run", lambda: None)
        svc = ProbeService(pool_size=2)
        server = ProbeServer(svc, socket_path="/tmp/bs_http_noauth.sock")

        async def _serve():
            await server.serve_http(host="127.0.0.1", port=0, token=None)

        task = asyncio.create_task(_serve())
        await asyncio.sleep(0.05)
        # No token -> no listener created.
        assert server._http is None
        server._stop.set()
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
        finally:
            await server.service.stop()

    asyncio.run(run())


@pytest.mark.unit
def test_authorization_token_parser():
    from blockchecks.service.server import _authorization_token

    assert _authorization_token("Bearer abc") == "abc"
    assert _authorization_token("bearer abc") == "abc"
    assert _authorization_token("Basic abc") is None
    assert _authorization_token("Bearer ") is None
    assert _authorization_token(None) is None


@pytest.mark.unit
def test_http_results_endpoint_reads_run_db(temp_db):
    """GET /api/results returns PASS strategies from a run DB (on-demand)."""
    import asyncio

    from blockchecks.service.probe_service import ProbeService
    from blockchecks.service.server import ProbeServer

    async def seed():
        await temp_db.log_tcp("fake:blob=stun:repeats=6", "discord.com", "PASS", 100.0, proto="tcp")
        await temp_db.log_tcp(
            "fake:blob=max_ru:repeats=6", "discord.com", "PASS", 120.0, proto="tcp"
        )
        await temp_db.flush()

    asyncio.run(seed())

    svc = ProbeService(pool_size=2)
    server = ProbeServer(svc, socket_path="/tmp/bs_results.sock")

    async def run():
        resp = await server._handle_results({"db": str(temp_db.path), "limit": 10})
        assert resp["status"] == "ok"
        assert resp["db"] == str(temp_db.path)
        names = [s["strategy"] for s in resp["tcp"]]
        assert "fake:blob=stun:repeats=6" in names
        assert "fake:blob=max_ru:repeats=6" in names

    asyncio.run(run())


@pytest.mark.unit
def test_http_logs_endpoint_tails_python_log(monkeypatch, tmp_path):
    async def run():
        from blockchecks.engine import log as logmod

        log_file = tmp_path / "blockchecks.log"
        log_file.write_text("line-a\nline-b\n")
        monkeypatch.setattr(logmod, "python_log_path", lambda: log_file)
        server, port, task = await _start_http_server(monkeypatch)
        try:
            client = _HttpProbe(port, token=HTTP_TOKEN)
            code, resp = await client.request("GET", "/api/logs?source=python&tail=10&offset=0")
            assert code == 200
            assert resp.get("status") == "ok"
            assert resp.get("ok") is True
            data = resp.get("data") or resp
            assert data["lines"] == ["line-a", "line-b"]
            assert data["source"] == "python"
            assert data["truncated"] is False
        finally:
            await _stop_http_server(server, task)

    asyncio.run(run())


@pytest.mark.unit
def test_http_logs_rejects_unknown_source(monkeypatch):
    async def run():
        server, port, task = await _start_http_server(monkeypatch)
        try:
            client = _HttpProbe(port, token=HTTP_TOKEN)
            code, resp = await client.request("GET", "/api/logs?source=../../etc/passwd")
            assert code == 200
            assert resp.get("ok") is False
            assert "invalid source" in (resp.get("error") or "")
        finally:
            await _stop_http_server(server, task)

    asyncio.run(run())


@pytest.mark.unit
def test_http_set_debug_post(monkeypatch):
    async def run():
        from blockchecks.engine.log import set_debug_mode

        server, port, task = await _start_http_server(monkeypatch)
        try:
            client = _HttpProbe(port, token=HTTP_TOKEN)
            code, resp = await client.request("POST", "/api/set-debug", {"enabled": True})
            assert code == 200
            assert resp.get("ok") is True
            data = resp.get("data") or resp
            assert data.get("enabled") is True
        finally:
            set_debug_mode(False)
            await _stop_http_server(server, task)

    asyncio.run(run())
