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
from collections.abc import Callable

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


def drop_ns_epoch(ns_name: str) -> None:
    """Forget the epoch counter for a destroyed ns (keeps long-lived daemons lean)."""
    with _NS_EPOCHS_LOCK:
        _NS_EPOCHS.pop(ns_name, None)


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
    # Host-mode slot (docs/hostmode.md §8): "host-qN-<pid>" runs WITHOUT
    # netns exec, under the dedicated probe uid so nft `meta skuid` matches —
    # a plain "host" name must NEVER appear here (it would netns-exec).
    if ns_name.startswith("host-q"):
        from blockchecks.engine.config import HOST_PROBE_USER

        return [
            "sudo",
            "-n",
            "-u",
            HOST_PROBE_USER,
            "-E",
            py,
            "-m",
            "blockchecks.service.in_ns_workers",
            "--mode",
            "curl",
        ]
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


#: Sentinel returned by :meth:`_PersistentCurlWorker.invoke` when the caller's
#: ``abort_poll`` fired (DPI already killed the flow — waiting the full curl
#: timeout is wasted wall time; AUDIT §19 D1).
_WORKER_ABORTED = object()


def _readline_timed_stepped(
    fd: int, timeout: float, remainder: bytearray, *, poll: Callable[[], bool] | None, interval: float
) -> str | object | None:
    """Like :func:`_readline_timed`, but between select steps the caller's
    ``abort_poll`` runs; True → worker is SIGKILLed by ``invoke`` and the
    sentinel ``_WORKER_ABORTED`` is returned. Full-line/EOF semantics match
    the plain variant (os.read + remainder buffer — §11 lesson)."""
    deadline = time.monotonic() + timeout
    while True:
        if (nl := remainder.find(b"\n")) >= 0:
            line = bytes(remainder[:nl])
            del remainder[: nl + 1]
            return line.decode("utf-8", errors="replace")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        ready, _, _ = select.select([fd], [], [], min(remaining, interval))
        if not ready:
            if poll is not None and poll():
                return _WORKER_ABORTED
            continue
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
        self._invoke_count = 0
        self._recycle_every = int(os.environ.get("BLOCKCHECKS_WORKER_RECYCLE_EVERY", "0") or 0)

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

    def invoke(
        self,
        payload: dict,
        timeout: float,
        *,
        abort_poll: Callable[[], bool] | None = None,
        poll_interval: float = 0.1,
    ) -> tuple[dict, bool]:
        """Run one probe. Returns ``(data, aborted)``.

        ``abort_poll`` (D1 early abort): checked between stdout select steps;
        True → the worker process is SIGKILLed (its stdout pipe dies with it —
        no partial-line leak into the next probe) and ``(fail, True)`` is
        returned. The caller MUST release the worker from the cache and bump
        the ns epoch so the next probe spawns a fresh process.
        """
        aborted = False
        self._invoke_count += 1
        with self._io_lock:
            if self._proc is None or self._proc.poll() is not None:
                self._start()
            proc = self._proc
            if proc is None or proc.stdin is None or proc.stdout is None:
                return {**_FAIL, "error": "worker start failed"}, False
            try:
                proc.stdin.write(json.dumps(payload).encode("utf-8") + b"\n")
                proc.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                self._kill()
                return {**_FAIL, "error": f"worker write: {exc}"[:120]}, False
            try:
                fd = proc.stdout.fileno()
            except (AttributeError, OSError, ValueError):
                self._kill()
                return {**_FAIL, "error": "worker stdout has no fd"}, False
            if abort_poll is not None:
                line = _readline_timed_stepped(
                    fd, timeout, self._stdout_buf, poll=abort_poll, interval=poll_interval
                )
                if line is _WORKER_ABORTED:
                    aborted = True
                    line = None
            else:
                line = _readline_timed(fd, timeout, self._stdout_buf)
            if line is None:
                err_tail = self._stderr_buf.decode("utf-8", errors="replace")[-120:]
                # Poll before the kill: after SIGKILL poll() reports -9 even
                # for a worker that died naturally, which would mislabel the
                # failure and poison fail_phase statistics (AUDIT §7.3).
                poll = proc.poll()
                self._kill()
                if poll is not None:
                    detail = f": {err_tail}" if err_tail else " (no stderr)"
                    return {**_FAIL, "error": f"worker died (exit {poll}){detail}"[:160]}, aborted
                if aborted:
                    return {**_FAIL, "error": "aborted by abort_poll"}, True
                return {**_FAIL, "error": f"timeout after {timeout:.0f}s"}, False
            data = _loads_probe_json(line)
            # §7.3 recycle-by-counter: the persistent worker accumulates curl
            # Sessions/handles across a 20h campaign; respawn after N probes
            # (env knob, 0 = off). Kill AFTER the result is read — the pipe
            # contract stays intact, the next invoke spawns a fresh worker.
            if self._recycle_every and self._invoke_count >= self._recycle_every:
                self._kill()
                self._invoke_count = 0
            return data, False

    def close(self) -> None:
        with self._io_lock:
            self._kill()


_INPROC_EPERM_WARNED = False


class _InprocCurlWorker:
    """Probe curl calls in-process via per-thread ``setns`` (P2, AUDIT §21).

    Netns is a process-wide property on Linux, BUT ``setns(CLONE_NEWNET)`` is
    per-thread on modern kernels (verified 2026-09-10: two threads held two
    distinct netns concurrently while the main thread stayed on the host ns).
    A probe thread enters the target netns, runs the SAME
    ``run_curl_worker_payload`` contract the subprocess worker executes, and
    restores the host ns in ``finally`` — sockets created by libcurl inherit
    the calling thread's nsproxy, so TLS/JA4/DoH-pin semantics are identical.

    Differences from :class:`_PersistentCurlWorker` (opt-in mode):
    - no subprocess: no per-netns python RSS (~31 MiB peak each, measured);
    - ``abort_poll`` (D1) is IGNORED — curl_cffi 0.16.1 does not support
      XFERINFOFUNCTION (setopt error 20219), so an in-flight transfer cannot
      be cleanly interrupted; D1 stays a subprocess-mode feature. Warned once.
    - §7.3 recycle counter does not apply (no accumulating process; Sessions
      are created and closed per probe inside the checker).
    """

    def __init__(self, ns_name: str, py: str) -> None:
        self.ns_name = ns_name
        self.py = py
        self._io_lock = threading.Lock()
        self._invoke_count = 0

    @staticmethod
    def _host_ns_fd() -> int:
        # Called from the invoking thread while it is still on the host ns —
        # thread-self points at THIS thread's ns (never another worker's).
        return os.open("/proc/thread-self/ns/net", os.O_RDONLY)

    def invoke(
        self,
        payload: dict,
        timeout: float,
        *,
        abort_poll: Callable[[], bool] | None = None,
        poll_interval: float = 0.1,
    ) -> tuple[dict, bool]:
        """Run one probe in-process inside the netns. Returns ``(data, aborted)``.

        The (data, aborted) contract mirrors the subprocess worker so callers
        stay unchanged; inproc never aborts (see class docstring).
        ``timeout`` bounds nothing here directly — the checker applies its own
        per-request timeouts (the subprocess wall budget is only about the
        worker process, which does not exist in this mode).
        """
        global _INPROC_EPERM_WARNED
        del timeout, poll_interval
        if abort_poll is not None and not _INPROC_EPERM_WARNED:
            # D1 early abort is a subprocess-mode feature (see class docstring);
            # say it once, do not spam per probe.
            _INPROC_EPERM_WARNED = True
            log.info(
                "probe-worker=inproc: abort_poll ignored (curl_cffi 0.16.1 has no "
                "XFERINFOFUNCTION — D1 early abort stays a subprocess-mode feature)"
            )
        self._invoke_count += 1
        with self._io_lock:
            from blockchecks.service.in_ns_workers import run_curl_worker_payload

            host_fd = self._host_ns_fd()
            try:
                ns_fd = os.open(f"/var/run/netns/{self.ns_name}", os.O_RDONLY)
            except OSError as exc:
                os.close(host_fd)
                return {**_FAIL, "error": f"inproc netns fd: {exc}"[:120]}, False
            try:
                os.setns(ns_fd, os.CLONE_NEWNET)
            except OSError as exc:
                os.close(ns_fd)
                os.close(host_fd)
                if exc.errno == 1:  # EPERM: non-root runner — caller falls back
                    return {**_FAIL, "error": "inproc setns: EPERM"}, False
                return {**_FAIL, "error": f"inproc setns: {exc}"[:120]}, False
            try:
                os.close(ns_fd)
                data = run_curl_worker_payload(payload)
                return data, False
            except Exception as exc:  # noqa: BLE001 — probe must not kill the runner
                log.warning("inproc probe payload failed: %s", exc)
                return {**_FAIL, "error": f"inproc: {exc}"[:120]}, False
            finally:
                try:
                    os.setns(host_fd, os.CLONE_NEWNET)
                except OSError as exc:
                    log.error("inproc setns back to host ns failed: %s", exc)
                finally:
                    os.close(host_fd)

    def close(self) -> None:
        # No process to kill; release just drops the registry entry.
        self._invoke_count = 0


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


def _get_worker(ns_name: str, py: str, worker_mode: str = "subprocess") -> object:
    key = worker_cache_key(ns_name, py)
    with _WORKERS_LOCK:
        worker = _WORKERS.get(key)
        if worker is None:
            if worker_mode == "inproc":
                worker = _InprocCurlWorker(ns_name, py)
            else:
                worker = _PersistentCurlWorker(ns_name, py)
            _WORKERS[key] = worker
        return worker


def invoke_curl_probe_worker(
    ns_name: str,
    py: str,
    payload: dict,
    timeout: float,
    *,
    abort_poll: Callable[[], bool] | None = None,
    poll_interval: float = 0.1,
    worker_mode: str = "subprocess",
) -> dict:
    """Run curl probe via a persistent in-ns worker; JSON-lines per request.

    On malformed stdout, returns a failure-shaped dict (never raises JSONDecodeError).
    On subprocess timeout, returns a timeout-shaped failure dict (never raises
    TimeoutExpired) — a hung worker must not lose the whole batch.
    Stderr is kept separate so Python/dependency warnings cannot pollute JSON.

    With ``abort_poll`` (D1): the poll runs between stdout select steps; on
    True the worker is SIGKILLed, released from the cache and the ns epoch is
    bumped — the next probe spawns a fresh worker (spawn cost ≈ 0.1s vs the
    saved curl wall on every FAIL probe). Subprocess mode only — inproc mode
    cannot interrupt an in-flight transfer (no XFERINFOFUNCTION in
    curl_cffi 0.16.1) and ignores the poll (logged once).

    ``worker_mode="inproc"`` (opt-in, P2): runs the probe payload in-process
    via per-thread setns — no per-netns python process (~31 MiB peak RSS
    each). Host slots force subprocess (skuid bcprobe guard).
    """
    global _INPROC_EPERM_WARNED
    mode = worker_mode if worker_mode in ("subprocess", "inproc") else "subprocess"
    if worker_mode not in ("subprocess", "inproc"):
        log.warning("unknown worker_mode %r — subprocess worker", worker_mode)
    # Guard (P2): host slots MUST keep the subprocess worker — the nft
    # ``meta skuid`` rule matches the dedicated probe uid (bcprobe); an
    # in-process probe runs as the runner uid and would take the raw path
    # (false FAILs). docs/hostmode.md §8.
    if mode == "inproc" and ns_name.startswith("host-q"):
        log.warning("probe-worker=inproc unsupported for host slots (skuid bcprobe) — subprocess")
        mode = "subprocess"
    try:
        if mode == "inproc":
            data, aborted = _get_worker(ns_name, py, "inproc").invoke(
                payload, timeout, abort_poll=abort_poll, poll_interval=poll_interval
            )
            if data.get("error") == "inproc setns: EPERM":
                # Explicit fallback (never silent): non-root runner cannot
                # setns — the subprocess worker goes through sudo inside the
                # engine, as before. Warn once per process.
                if not _INPROC_EPERM_WARNED:
                    _INPROC_EPERM_WARNED = True
                    log.warning(
                        "probe-worker=inproc: setns EPERM (non-root) — subprocess worker"
                    )
            elif aborted:
                release_curl_probe_worker(ns_name, py)
                bump_ns_epoch(ns_name)
            return data
        data, aborted = _get_worker(ns_name, py).invoke(
            payload, timeout, abort_poll=abort_poll, poll_interval=poll_interval
        )
        if aborted:
            release_curl_probe_worker(ns_name, py)
            bump_ns_epoch(ns_name)
        return data
    except Exception as e:
        log.warning("invoke_curl_probe_worker(%s) failed: %s", ns_name, e)
        return {**_FAIL, "error": str(e)[:120]}
