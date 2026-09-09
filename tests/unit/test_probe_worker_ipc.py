"""Real-pipe IPC tests for persistent curl worker (do not mock _readline_timed)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

from blockchecks.service import probe as probe_mod
from blockchecks.service.probe import (
    _readline_timed,
    invoke_curl_probe_worker,
    release_curl_probe_worker,
)

_STUB = (
    "import json,sys\n"
    "for raw in sys.stdin:\n"
    "    print(json.dumps({'success': True, 'http_code': 200, 'latency_ms': 1}), flush=True)\n"
)


@pytest.fixture(autouse=True)
def _clear_workers():
    probe_mod._WORKERS.clear()
    probe_mod._NS_EPOCHS.clear()
    yield
    for key in list(probe_mod._WORKERS):
        release_curl_probe_worker(key[0], key[1])
    probe_mod._WORKERS.clear()
    probe_mod._NS_EPOCHS.clear()


@pytest.mark.unit
def test_readline_timed_reads_real_pipe():
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import json,sys; print(json.dumps({'ok': 1}), flush=True); sys.stdin.read()",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )
    try:
        assert proc.stdout is not None
        buf = bytearray()
        t0 = time.monotonic()
        line = _readline_timed(proc.stdout.fileno(), 2.0, buf)
        elapsed = time.monotonic() - t0
        assert line is not None
        assert json.loads(line)["ok"] == 1
        assert elapsed < 1.0
    finally:
        proc.kill()
        proc.wait(timeout=5)


@pytest.mark.unit
def test_readline_timed_keeps_remainder_across_lines():
    r_fd, w_fd = os.pipe()
    try:
        os.write(w_fd, b'{"a":1}\n{"b":2}\n')
        buf = bytearray()
        first = _readline_timed(r_fd, 1.0, buf)
        second = _readline_timed(r_fd, 1.0, buf)
        assert json.loads(first or "") == {"a": 1}
        assert json.loads(second or "") == {"b": 2}
    finally:
        os.close(r_fd)
        os.close(w_fd)


@pytest.mark.unit
def test_persistent_worker_roundtrip_real_pipe(monkeypatch):
    monkeypatch.setattr(
        probe_mod,
        "_worker_cmd",
        lambda _ns, _py: [sys.executable, "-c", _STUB],
    )
    real_popen = probe_mod.sp.Popen
    n = {"n": 0}

    def counting_popen(*args, **kwargs):
        n["n"] += 1
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(probe_mod.sp, "Popen", counting_popen)
    payload = {"mode": "single", "request": {"domain": "x"}}
    ns, py = "bs-ipc-test", sys.executable
    try:
        out1 = invoke_curl_probe_worker(ns, py, payload, 2.0)
        out2 = invoke_curl_probe_worker(ns, py, payload, 2.0)
    finally:
        release_curl_probe_worker(ns, py)
    assert out1["success"] is True and out1["http_code"] == 200
    assert out2["success"] is True and out2["http_code"] == 200
    assert n["n"] == 1


@pytest.mark.unit
def test_early_abort_kills_worker_and_bumps_epoch(monkeypatch):
    """D1: abort_poll True mid-probe → worker SIGKILLed, cache released,
    epoch bumped, failure-shaped result returned (no partial-line leak)."""
    import time as _time

    stub = (
        "import sys, time\n"
        "line = sys.stdin.readline()\n"
        "time.sleep(30)\n"
        "print('{\"success\": true, \"http_code\": 200}')\n"
        "sys.stdout.flush()\n"
    )
    monkeypatch.setattr(
        probe_mod, "_worker_cmd", lambda _ns, _py: [sys.executable, "-c", stub]
    )
    ns, py = "bs-abort-test", sys.executable
    calls = {"poll": 0, "released": 0}

    monkeypatch.setattr(
        probe_mod, "release_curl_probe_worker", lambda *a, **k: calls.__setitem__("released", calls["released"] + 1)
    )
    payload = {"mode": "single", "request": {"domain": "x"}}

    def poll_true():
        calls["poll"] += 1
        return True

    t0 = _time.monotonic()
    try:
        out = invoke_curl_probe_worker(ns, py, payload, 20.0, abort_poll=poll_true, poll_interval=0.05)
    finally:
        release_curl_probe_worker(ns, py)
    elapsed = _time.monotonic() - t0
    assert out["success"] is False
    assert "aborted by abort_poll" in out["error"]
    assert elapsed < 3.0, f"abort took {elapsed:.1f}s — poll not firing"
    assert calls["released"] >= 1
    assert probe_mod.get_ns_epoch(ns) >= 1


@pytest.mark.unit
def test_early_abort_never_fires_when_poll_false(monkeypatch):
    """poll=False forever → normal full-timeout path (no kill, no release)."""
    stub = (
        "import sys, time\n"
        "line = sys.stdin.readline()\n"
        "time.sleep(0.5)\n"
        "print('{\"success\": true, \"http_code\": 200}')\n"
        "sys.stdout.flush()\n"
    )
    monkeypatch.setattr(probe_mod, "_worker_cmd", lambda _ns, _py: [sys.executable, "-c", stub])
    ns, py = "bs-abort-neg", sys.executable
    payload = {"mode": "single", "request": {"domain": "x"}}

    def poll_false():
        return False

    try:
        out = invoke_curl_probe_worker(ns, py, payload, 5.0, abort_poll=poll_false, poll_interval=0.05)
    finally:
        release_curl_probe_worker(ns, py)
    assert out["success"] is True and out["http_code"] == 200
