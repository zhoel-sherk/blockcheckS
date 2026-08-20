"""Tests for the streaming stall/QoS probe (mocked curl)."""

from __future__ import annotations

import pytest

from blockchecks.checkers.curl_probe import (
    StreamTriageResult,
    run_stream_triage_probe,
)


class _ChunkResp:
    def __init__(self, chunks, status=200):
        self.status_code = status
        self._chunks = chunks
        self.iter_done = False

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def iter_content(self, chunk_size=4096):
        yield from self._chunks
        self.iter_done = True


class _FakeSession:
    def __init__(self, resp, resolve=None):
        self._resp = resp
        self._resolve = resolve

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    @property
    def curl(self):
        return type("_C", (), {"setopt": lambda *a, **k: None})()

    def get(self, url, **kw):
        return self._resp


@pytest.mark.unit
def test_stall_at_16k(monkeypatch):
    import time

    import blockchecks.checkers.curl_probe as cp

    # send 16KB, then idle longer than STALL_IDLE_SEC → stall at 16k
    def gen():
        for _ in range(4):
            yield b"x" * 4096
        time.sleep(cp.STALL_IDLE_SEC + 0.5)

    resp = _ChunkResp(gen())
    monkeypatch.setattr(
        cp, "curl_cffi", type("_M", (), {"Session": lambda *a, **kw: _FakeSession(resp)})()
    )
    res = run_stream_triage_probe("https://x.test", timeout=8)
    assert res.phase == "data_stall_16k"
    assert res.total_bytes == 16 * 1024


@pytest.mark.unit
def test_full_stream_pass(monkeypatch):
    import blockchecks.checkers.curl_probe as cp

    chunks = [b"x" * 4096] * 16  # 64KB
    resp = _ChunkResp(chunks)
    monkeypatch.setattr(
        cp, "curl_cffi", type("_M", (), {"Session": lambda *a, **kw: _FakeSession(resp)})()
    )
    res = run_stream_triage_probe("https://x.test", timeout=5)
    assert res.total_bytes == 64 * 1024
    assert res.http_code == 200


@pytest.mark.unit
def test_stream_triage_result_to_dict():
    r = StreamTriageResult(phase="data_stall_16k", total_bytes=16384, read_rate_bps=1000)
    d = r.to_dict()
    assert d["phase"] == "data_stall_16k"
    assert d["total_bytes"] == 16384


@pytest.mark.unit
def test_tls_profile_detects_fingerprint_block(monkeypatch):
    from blockchecks.checkers import curl_probe as cp

    real = cp._probe_tls_profile

    def fake_probe(domain, profile, *, timeout, resolved_ip=None):
        # chrome fails, firefox passes, safari passes, bare fails → blocked
        return profile != "chrome124" and profile is not None

    monkeypatch.setattr(cp, "_probe_tls_profile", fake_probe)
    res = cp.run_tls_profile_probe("x.test", timeout=3)
    assert res.is_fingerprint_blocked is True
    assert res.profile_pass["chrome124"] is False
    assert res.profile_pass["firefox_120"] is True
    assert res.client_hello_len > 0
    cp._probe_tls_profile = real


@pytest.mark.unit
def test_tls_profile_all_pass(monkeypatch):
    from blockchecks.checkers import curl_probe as cp

    monkeypatch.setattr(cp, "_probe_tls_profile", lambda *a, **k: True)
    res = cp.run_tls_profile_probe("x.test", timeout=3)
    assert res.is_fingerprint_blocked is False
    assert res.client_hello_len == cp.TLS_PROFILE_CH_LEN["chrome124"]


@pytest.mark.unit
def test_tls_profile_result_to_dict():
    from blockchecks.checkers.curl_probe import TlsProfileResult

    r = TlsProfileResult(
        profile_pass={"chrome124": True}, client_hello_len=1740, is_fingerprint_blocked=False
    )
    d = r.to_dict()
    assert d["client_hello_len"] == 1740
    assert d["profile_pass"]["chrome124"] is True
