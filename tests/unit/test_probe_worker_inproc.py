"""P2 in-process probe worker (AUDIT §21): per-thread setns, dispatch, guards."""

from __future__ import annotations

import errno
import os

import pytest

from blockchecks.engine import config as cfg
from blockchecks.service import probe as probe_mod
from blockchecks.service.probe import (
    _InprocCurlWorker,
    invoke_curl_probe_worker,
    release_curl_probe_worker,
)

_PAYLOAD_RESULT = {"success": True, "http_code": 200, "latency_ms": 12.0}


@pytest.fixture(autouse=True)
def _clear_workers():
    probe_mod._WORKERS.clear()
    probe_mod._NS_EPOCHS.clear()
    probe_mod._INPROC_EPERM_WARNED = False
    yield
    for key in list(probe_mod._WORKERS):
        release_curl_probe_worker(key[0], key[1])
    probe_mod._WORKERS.clear()
    probe_mod._NS_EPOCHS.clear()


def _fake_ns_open(path, flags):
    if path.startswith("/var/run/netns/"):
        return os.open("/dev/null", os.O_RDONLY)  # dummy fd; invoke closes it
    return os.open.__wrapped__(path, flags) if hasattr(os.open, "__wrapped__") else _real_open(path, flags)


_real_open = os.open


@pytest.fixture
def setns_recorder(monkeypatch):
    """Patches run_curl_worker_payload + os.setns/os.open; returns setns calls.

    Patches via sys.modules (NOT ``import ... as``): PERF-7's pop/reimport
    leaves ``blockchecks.service`` attr pointing at an orphan module while
    sys.modules holds the original — ``import X.Y.Z as W`` resolves through
    the parent attr, ``from X.Y.Z import f`` (probe.invoke) through
    sys.modules; patching only one makes these tests order-dependent
    (pytest-randomly seed). Normalize both to the sys.modules object.
    """
    import sys

    mod = sys.modules.get("blockchecks.service.in_ns_workers")
    if mod is None:
        import importlib

        mod = importlib.import_module("blockchecks.service.in_ns_workers")
    parent = sys.modules["blockchecks.service"]
    if getattr(parent, "in_ns_workers", None) is not mod:
        monkeypatch.setattr(parent, "in_ns_workers", mod)
    monkeypatch.setattr(mod, "run_curl_worker_payload", lambda payload: dict(_PAYLOAD_RESULT))
    calls: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "setns", lambda fd, flag: calls.append((fd, flag)))
    monkeypatch.setattr(os, "open", _fake_ns_open)
    return calls


@pytest.mark.unit
def test_inproc_invoke_runs_payload_and_restores_ns(setns_recorder):
    """One probe: enter ns (setns once), run payload, restore host ns (setns back)."""
    worker = _InprocCurlWorker("bs-p-test-0000", "python")
    data, aborted = worker.invoke({"mode": "single", "request": {}}, 5.0)
    assert data == _PAYLOAD_RESULT
    assert aborted is False
    # enter + restore = exactly two setns calls on this thread
    assert len(setns_recorder) == 2


@pytest.mark.unit
def test_inproc_payload_exception_is_fail_dict(setns_recorder, monkeypatch):
    """A crashing payload must not kill the runner — fail-shaped dict."""
    import blockchecks.service.in_ns_workers as inw

    def boom(payload):
        raise RuntimeError("curl exploded")

    monkeypatch.setattr(inw, "run_curl_worker_payload", boom)
    worker = _InprocCurlWorker("bs-p-test-0000", "python")
    data, aborted = worker.invoke({"mode": "single", "request": {}}, 5.0)
    assert data["success"] is False
    assert "curl exploded" in data["error"]
    assert aborted is False
    # restore still ran (2 setns calls despite the exception)
    assert len(setns_recorder) == 2


@pytest.mark.unit
def test_inproc_setns_eperm_is_reported_for_fallback(monkeypatch):
    """Non-root runner: setns EPERM → explicit EPERM error for the dispatcher."""

    def deny(fd, flag):
        raise OSError(errno.EPERM, "Operation not permitted")

    import sys

    mod = sys.modules["blockchecks.service.in_ns_workers"]
    monkeypatch.setattr(mod, "run_curl_worker_payload", lambda payload: dict(_PAYLOAD_RESULT))
    monkeypatch.setattr(os, "setns", deny)
    monkeypatch.setattr(os, "open", _fake_ns_open)
    worker = _InprocCurlWorker("bs-p-test-0000", "python")
    data, _ = worker.invoke({"mode": "single", "request": {}}, 5.0)
    assert data["error"] == "inproc setns: EPERM"


@pytest.mark.unit
def test_inproc_missing_netns_fd_is_fail_dict(monkeypatch):
    """Recreated/missing netns: fd open fails → fail dict, no crash."""
    worker = _InprocCurlWorker("bs-p-no-such-ns", "python")
    data, _ = worker.invoke({"mode": "single", "request": {}}, 5.0)
    assert data["success"] is False
    assert "netns fd" in data["error"]


@pytest.mark.unit
def test_inproc_host_qnum_guard_forces_subprocess(monkeypatch):
    """Host slots must keep the subprocess worker (skuid bcprobe contract)."""
    captured = {}

    class FakeSubWorker:
        def __init__(self, ns, py):
            captured["mode_class"] = "subprocess"

        def invoke(self, payload, timeout, *, abort_poll=None, poll_interval=0.1):
            captured["invoked"] = True
            return _PAYLOAD_RESULT, False

        def close(self) -> None:
            pass

    monkeypatch.setattr(probe_mod, "_PersistentCurlWorker", FakeSubWorker)
    data = invoke_curl_probe_worker(
        "host-q220-123",
        "python",
        {"mode": "single", "request": {}},
        5.0,
        worker_mode="inproc",
    )
    assert data["success"] is True
    assert captured["mode_class"] == "subprocess"


@pytest.mark.unit
def test_dispatch_inproc_uses_inproc_worker(monkeypatch):
    """worker_mode=inproc on a netns name dispatches to the inproc class."""
    seen = {}

    class FakeInproc:
        def __init__(self, ns, py):
            seen["cls"] = "inproc"

        def invoke(self, payload, timeout, *, abort_poll=None, poll_interval=0.1):
            return _PAYLOAD_RESULT, False

        def close(self) -> None:
            pass

    monkeypatch.setattr(probe_mod, "_InprocCurlWorker", FakeInproc)
    data = invoke_curl_probe_worker(
        "bs-p-test-0000",
        "python",
        {"mode": "single", "request": {}},
        5.0,
        worker_mode="inproc",
    )
    assert data["success"] is True
    assert seen["cls"] == "inproc"


@pytest.mark.unit
def test_dispatch_unknown_mode_falls_back_to_subprocess():
    """Unknown worker_mode never reaches the inproc path (logged warning)."""
    data = invoke_curl_probe_worker(
        "bs-p-nomode-0000",
        "python",
        {"mode": "single", "request": {}},
        0.001,
        worker_mode="bogus",
    )
    # subprocess worker spawn attempt for a nonexistent ns → fail dict, not inproc
    assert data["success"] is False
    assert "inproc" not in (data.get("error") or "")


@pytest.mark.unit
def test_inproc_release_is_harmless():
    """release_curl_probe_worker drops the inproc entry without process kill."""
    worker = probe_mod._get_worker("bs-p-rel-0000", "python", "inproc")
    assert isinstance(worker, _InprocCurlWorker)
    release_curl_probe_worker("bs-p-rel-0000", "python")
    assert not any(k[0] == "bs-p-rel-0000" for k in probe_mod._WORKERS)


@pytest.mark.unit
def test_resolve_probe_worker_defaults_and_guards():
    """Flag/env resolution: default subprocess, inproc opt-in, unknown → error."""

    class A:
        probe_worker: str | None = None

    assert cfg.resolve_probe_worker(A()) == "subprocess"
    A.probe_worker = "inproc"
    assert cfg.resolve_probe_worker(A()) == "inproc"
    A.probe_worker = "subprocess"
    assert cfg.resolve_probe_worker(A()) == "subprocess"
    A.probe_worker = "bogus"
    with pytest.raises(ValueError):
        cfg.resolve_probe_worker(A())
    A.probe_worker = None
    monkeypatch_env = {"BLOCKCHECKS_PROBE_WORKER": "inproc"}
    old = os.environ.get("BLOCKCHECKS_PROBE_WORKER")
    try:
        os.environ["BLOCKCHECKS_PROBE_WORKER"] = "inproc"
        assert cfg.resolve_probe_worker(A()) == "inproc"
    finally:
        if old is None:
            os.environ.pop("BLOCKCHECKS_PROBE_WORKER", None)
        else:
            os.environ["BLOCKCHECKS_PROBE_WORKER"] = old
    del monkeypatch_env

@pytest.mark.unit
def test_run_tcp_check_forwards_worker_mode():
    """_run_tcp_check accepts worker_mode and forwards it to the invoke site."""
    import pathlib as _pl

    from blockchecks.service import in_ns_workers as inw

    src = _pl.Path(inw.__file__).read_text(encoding="utf-8")
    assert 'worker_mode: str = "subprocess"' in src
    assert "worker_mode=worker_mode" in src  # invoke call site forwards the kwarg


@pytest.mark.unit
def test_dns_pin_service_inherits_runner_mode(monkeypatch):
    """DnsPinService forwards worker_mode into the _run_tcp_check call."""
    import asyncio

    import blockchecks.engine.dns_pin_service as dps

    captured: dict = {}

    def fake_check(*args, **kwargs):
        # to_thread calls this SYNC function in a thread
        captured["worker_mode"] = kwargs.get("worker_mode")
        return {"success": True}

    monkeypatch.setattr(dps, "_run_tcp_check", fake_check)

    class Cache:
        def pins(self):
            return {}

        def domains(self):
            return ["example.com"]

        def candidates(self, domain):
            return ["192.0.2.1"]

        def set_pins(self, pins):
            pass

        def pinned_ip(self, domain):
            return None

        def add_pin(self, domain, ip):
            pass

    svc = dps.DnsPinService(
        dns_cache=Cache(),
        pinned_path="",
        acquire_ns=_async_noop_acquire,
        release_ns=_async_noop_release,
        worker_mode="inproc",
    )
    ok = asyncio.run(svc.probe_pin_ip("example.com", "192.0.2.1"))
    assert ok is True
    assert captured["worker_mode"] == "inproc"


async def _async_noop_acquire():
    return "bs-p-fake"


async def _async_noop_release(ns):
    pass


@pytest.mark.unit
def test_dns_pin_service_default_is_subprocess(monkeypatch):
    """Without an explicit mode the pin service keeps the subprocess contract."""
    import asyncio

    import blockchecks.engine.dns_pin_service as dps

    captured: dict = {}

    def fake_check(*args, **kwargs):
        captured["worker_mode"] = kwargs.get("worker_mode")
        return {"success": False}

    monkeypatch.setattr(dps, "_run_tcp_check", fake_check)

    class Cache:
        def pins(self):
            return {}

        def domains(self):
            return ["example.com"]

        def candidates(self, domain):
            return ["192.0.2.1"]

        def set_pins(self, pins):
            pass

        def pinned_ip(self, domain):
            return None

        def add_pin(self, domain, ip):
            pass

    svc = dps.DnsPinService(
        dns_cache=Cache(),
        pinned_path="",
        acquire_ns=_async_noop_acquire,
        release_ns=_async_noop_release,
    )
    asyncio.run(svc.probe_pin_ip("example.com", "192.0.2.1"))
    assert captured["worker_mode"] == "subprocess"
