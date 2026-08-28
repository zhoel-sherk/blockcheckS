"""Run a curl probe as a Python subprocess inside a netns (in_ns_workers --mode curl)."""

from __future__ import annotations

import json
import logging
import os
import select
import signal
import subprocess as sp
import threading
import time

from blockchecks.checkers.curl_probe import CurlProbeRequest

log = logging.getLogger(__name__)

_FAIL = {
    "success": False,
    "http_code": 0,
    "latency_ms": 0,
    "content_len": 0,
    "content_ok": False,
    "throttled": False,
    "read_rate_bps": 0,
}

_STDERR_RING = 8192
WorkerCacheKey = tuple[str, str, int]
_WORKERS: dict[WorkerCacheKey, _PersistentCurlWorker] = {}
_WORKERS_LOCK = threading.Lock()
_NS_EPOCHS: dict[str, int] = {}
_NS_EPOCHS_LOCK = threading.Lock()


def bump_ns_epoch(ns_name: str) -> int:
    """Increment pool epoch for *ns_name* (call on netns create/recreate)."""
    with _NS_EPOCHS_LOCK:
        epoch = _NS_EPOCHS.get(ns_name, 0) + 1
        _NS_EPOCHS[ns_name] = epoch
        return epoch


def get_ns_epoch(ns_name: str) -> int:
    """Current pool epoch for *ns_name* (0 when never bumped)."""
    with _NS_EPOCHS_LOCK:
        return _NS_EPOCHS.get(ns_name, 0)


def worker_cache_key(ns_name: str, py: str) -> WorkerCacheKey:
    """Persistent curl worker dict key: (ns_name, python, pool_epoch)."""
    return (ns_name, py, get_ns_epoch(ns_name))


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
        "blockchecks.service.in_ns_workers",
        "--mode",
        "curl",
    ]


def _readline_timed(fd: int, timeout: float, remainder: bytearray) -> str | None:
    """Read one stdout line via os.read; None on timeout/EOF.

    Must not mix select() with buffered TextIOWrapper.read(): the wrapper
    slurps the whole JSON line on the first byte, then select waits on an
    empty kernel pipe until the wall timeout (composite/scan fake FAIL).
    """
    deadline = time.monotonic() + timeout
    while True:
        if (nl := remainder.find(b"\n")) >= 0:
            line = bytes(remainder[:nl])
            del remainder[: nl + 1]
            return line.decode("utf-8", errors="replace")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            return None
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            return None
        if not chunk:
            if not remainder:
                return None
            line = bytes(remainder)
            remainder.clear()
            return line.decode("utf-8", errors="replace")
        remainder.extend(chunk)


def _drain_stderr_fd(fd: int, stop: threading.Event, buf: bytearray) -> None:
    """Keep stderr PIPE from filling; retain a small tail for death diagnostics."""
    try:
        os.set_blocking(fd, False)
    except OSError:
        pass
    while not stop.is_set():
        ready, _, _ = select.select([fd], [], [], 0.1)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 4096)
        except BlockingIOError:
            continue
        except OSError:
            break
        if not chunk:
            break
        buf.extend(chunk)
        overflow = len(buf) - _STDERR_RING
        if overflow > 0:
            del buf[:overflow]
            log.debug("curl worker stderr ring overflow, dropped %d bytes", overflow)


def _kill_worker_tree(proc: sp.Popen[bytes] | None) -> None:
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
        self._proc: sp.Popen[bytes] | None = None
        self._io_lock = threading.Lock()
        self._stdout_buf = bytearray()
        self._stderr_buf = bytearray()
        self._stderr_stop: threading.Event | None = None
        self._stderr_thread: threading.Thread | None = None

    def _stop_stderr_drain(self) -> None:
        if self._stderr_stop is not None:
            self._stderr_stop.set()
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=0.5)
        self._stderr_stop = None
        self._stderr_thread = None

    def _start_stderr_drain(self, proc: sp.Popen[bytes]) -> None:
        self._stop_stderr_drain()
        self._stderr_buf = bytearray()
        if proc.stderr is None:
            return
        try:
            fd = int(proc.stderr.fileno())
        except (AttributeError, OSError, TypeError, ValueError):
            return
        stop = threading.Event()
        thread = threading.Thread(
            target=_drain_stderr_fd,
            args=(fd, stop, self._stderr_buf),
            daemon=True,
            name="curl-worker-stderr",
        )
        self._stderr_stop = stop
        self._stderr_thread = thread
        thread.start()

    def _start(self) -> None:
        self._kill()
        self._stdout_buf = bytearray()
        self._proc = sp.Popen(
            _worker_cmd(self.ns_name, self.py),
            stdin=sp.PIPE,
            stdout=sp.PIPE,
            stderr=sp.PIPE,
            bufsize=0,
            start_new_session=True,
        )
        self._start_stderr_drain(self._proc)

    def _kill(self) -> None:
        self._stop_stderr_drain()
        _kill_worker_tree(self._proc)
        self._proc = None
        self._stdout_buf = bytearray()

    def invoke(self, payload: dict, timeout: float) -> dict:
        with self._io_lock:
            if self._proc is None or self._proc.poll() is not None:
                self._start()
            proc = self._proc
            if proc is None or proc.stdin is None or proc.stdout is None:
                return {**_FAIL, "error": "worker start failed"}
            try:
                proc.stdin.write(json.dumps(payload).encode("utf-8") + b"\n")
                proc.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                self._kill()
                return {**_FAIL, "error": f"worker write: {exc}"[:120]}
            try:
                fd = proc.stdout.fileno()
            except (AttributeError, OSError, ValueError):
                self._kill()
                return {**_FAIL, "error": "worker stdout has no fd"}
            line = _readline_timed(fd, timeout, self._stdout_buf)
            if line is None:
                err_tail = self._stderr_buf.decode("utf-8", errors="replace")[-120:]
                self._kill()
                if proc.poll() is not None and err_tail:
                    return {**_FAIL, "error": f"worker died: {err_tail}"}
                return {**_FAIL, "error": f"timeout after {timeout:.0f}s"}
            return _loads_probe_json(line)

    def close(self) -> None:
        with self._io_lock:
            self._kill()


def release_curl_probe_worker(ns_name: str, py: str | None = None) -> None:
    """Stop the persistent curl worker for *ns_name* (best-effort, all epochs)."""
    with _WORKERS_LOCK:
        if py is None:
            keys = [k for k in _WORKERS if k[0] == ns_name]
        else:
            keys = [k for k in _WORKERS if k[0] == ns_name and k[1] == py]
        for key in keys:
            worker = _WORKERS.pop(key, None)
            if worker is not None:
                worker.close()


def _get_worker(ns_name: str, py: str) -> _PersistentCurlWorker:
    key = worker_cache_key(ns_name, py)
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
        log.warning("invoke_curl_probe_worker(%s) failed: %s", ns_name, e)
        return {**_FAIL, "error": str(e)[:120]}
