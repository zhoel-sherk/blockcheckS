"""Run a curl probe as a Python subprocess inside a netns (in_ns_workers --mode curl)."""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess as sp
import threading
import time

from blockchecks.checkers.curl_probe import CurlProbeRequest

_FAIL = {
    "success": False,
    "http_code": 0,
    "latency_ms": 0,
    "content_len": 0,
    "content_ok": False,
    "throttled": False,
    "read_rate_bps": 0,
}

_WORKERS: dict[tuple[str, str], _PersistentCurlWorker] = {}
_WORKERS_LOCK = threading.Lock()


def probe_request_dict(req: CurlProbeRequest) -> dict:
    """Serialize a CurlProbeRequest for the worker stdin JSON payload."""
    return {
        "domain": req.domain,
        "timeout": req.timeout,
        "resolved_ip": req.resolved_ip,
        "resolve_name": req.resolve_name,
        "curl_url": req.curl_url,
        "disable_ech": req.disable_ech,
        "googlevideo": req.googlevideo,
        "ggc": req.ggc,
        "ytcdn": req.ytcdn,
        "ytcdn_proxy": req.ytcdn_proxy,
        "ytcdn_bare": req.ytcdn_bare,
        "protocol": req.protocol,
    }


def _loads_probe_json(out: str | None) -> dict:
    """Parse worker JSON; tolerate leading/trailing warning text on stdout."""
    text = (out or "").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            pass
    return {**_FAIL, "error": f"parse: {text[:100]}"}


def _worker_cmd(ns_name: str, py: str) -> list[str]:
    return [
        "sudo",
        "-E",
        "ip",
        "netns",
        "exec",
        ns_name,
        py,
        "-m",
        "blockchecks.engine.in_ns_workers",
        "--mode",
        "curl",
    ]


def _readline_timed(pipe: sp.TextIOWrapper | None, timeout: float) -> str | None:
    """Read one stdout line with a wall-clock deadline; None on timeout/EOF."""
    if pipe is None:
        return None
    fd = pipe.fileno()
    deadline = time.monotonic() + timeout
    chunks: list[str] = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            return None
        ch = pipe.read(1)
        if ch == "":
            return "".join(chunks) if chunks else None
        if ch == "\n":
            return "".join(chunks)
        chunks.append(ch)


def _kill_worker_tree(proc: sp.Popen[str] | None) -> None:
    if proc is None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass
    try:
        proc.wait(timeout=5)
    except sp.TimeoutExpired:
        pass


class _PersistentCurlWorker:
    """One long-lived in-ns worker per netns; JSON request/response per line."""

    def __init__(self, ns_name: str, py: str) -> None:
        self.ns_name = ns_name
        self.py = py
        self._proc: sp.Popen[str] | None = None
        self._io_lock = threading.Lock()

    def _start(self) -> None:
        self._kill()
        self._proc = sp.Popen(
            _worker_cmd(self.ns_name, self.py),
            stdin=sp.PIPE,
            stdout=sp.PIPE,
            stderr=sp.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
        )

    def _kill(self) -> None:
        _kill_worker_tree(self._proc)
        self._proc = None

    def invoke(self, payload: dict, timeout: float) -> dict:
        with self._io_lock:
            if self._proc is None or self._proc.poll() is not None:
                self._start()
            proc = self._proc
            if proc is None or proc.stdin is None or proc.stdout is None:
                return {**_FAIL, "error": "worker start failed"}
            try:
                proc.stdin.write(json.dumps(payload) + "\n")
                proc.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                self._kill()
                return {**_FAIL, "error": f"worker write: {exc}"[:120]}
            line = _readline_timed(proc.stdout, timeout)
            if line is None:
                self._kill()
                if proc.poll() is not None:
                    err_tail = ""
                    if proc.stderr is not None:
                        try:
                            err_tail = (proc.stderr.read() or "")[:120]
                        except OSError:
                            pass
                    if err_tail:
                        return {**_FAIL, "error": f"worker died: {err_tail}"}
                return {**_FAIL, "error": f"timeout after {timeout:.0f}s"}
            return _loads_probe_json(line)

    def close(self) -> None:
        with self._io_lock:
            self._kill()


def release_curl_probe_worker(ns_name: str, py: str | None = None) -> None:
    """Stop the persistent curl worker for *ns_name* (best-effort)."""
    with _WORKERS_LOCK:
        if py is None:
            keys = [k for k in _WORKERS if k[0] == ns_name]
        else:
            keys = [(ns_name, py)]
        for key in keys:
            worker = _WORKERS.pop(key, None)
            if worker is not None:
                worker.close()


def _get_worker(ns_name: str, py: str) -> _PersistentCurlWorker:
    key = (ns_name, py)
    with _WORKERS_LOCK:
        worker = _WORKERS.get(key)
        if worker is None:
            worker = _PersistentCurlWorker(ns_name, py)
            _WORKERS[key] = worker
        return worker


def invoke_curl_probe_worker(ns_name: str, py: str, payload: dict, timeout: float) -> dict:
    """Run curl probe via a persistent in-ns worker; JSON-lines per request.

    On malformed stdout, returns a failure-shaped dict (never raises JSONDecodeError).
    On subprocess timeout, returns a timeout-shaped failure dict (never raises
    TimeoutExpired) — a hung worker must not lose the whole batch.
    Stderr is kept separate so Python/dependency warnings cannot pollute JSON.
    """
    try:
        return _get_worker(ns_name, py).invoke(payload, timeout)
    except Exception as e:
        return {**_FAIL, "error": str(e)[:120]}
