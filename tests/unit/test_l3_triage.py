"""Tests for L3/L4 blackhole and DNS sinkhole classification."""

from __future__ import annotations

import errno

import pytest

from blockchecks.checkers.dns_secure import _sinkhole_ip
from blockchecks.checkers.l3_probe import (
    L3ProbeResult,
    _is_icmp_block,
    _parse_icmp,
    probe_l3,
)
from blockchecks.engine.fail_phase import FailPhase


@pytest.mark.unit
def test_sinkhole_filter_detects_poisoned_ips():
    assert _sinkhole_ip(["127.0.0.1"]) == ["127.0.0.1"]
    assert _sinkhole_ip(["0.0.0.0"]) == ["0.0.0.0"]
    assert _sinkhole_ip(["198.18.0.1"]) == ["198.18.0.1"]
    assert _sinkhole_ip(["198.51.100.7"]) == ["198.51.100.7"]
    assert _sinkhole_ip(["203.0.113.9"]) == ["203.0.113.9"]
    assert _sinkhole_ip(["10.0.0.1"]) == ["10.0.0.1"]
    assert _sinkhole_ip(["172.16.0.1"]) == ["172.16.0.1"]
    assert _sinkhole_ip(["192.168.1.1"]) == ["192.168.1.1"]
    assert _sinkhole_ip(["240.1.1.1"]) == ["240.1.1.1"]
    assert _sinkhole_ip(["2001:db8::1"]) == ["2001:db8::1"]


@pytest.mark.unit
def test_sinkhole_filter_clean_ips():
    assert _sinkhole_ip(["8.8.8.8"]) == []
    assert _sinkhole_ip(["1.1.1.1", "8.8.8.8"]) == []
    assert _sinkhole_ip(["142.251.38.110"]) == []


@pytest.mark.unit
def test_sinkhole_filter_mixed():
    assert _sinkhole_ip(["8.8.8.8", "127.0.0.1"]) == ["127.0.0.1"]
    assert _sinkhole_ip(["127.0.0.1", "8.8.8.8", "198.18.0.1"]) == [
        "127.0.0.1",
        "198.18.0.1",
    ]


@pytest.mark.unit
def test_sinkhole_filter_invalid():
    assert _sinkhole_ip(["not-an-ip", ""]) == []
    assert _sinkhole_ip([]) == []


@pytest.mark.unit
def test_icmp_block_codes():
    assert _is_icmp_block(3, 13) is True  # admin prohibited
    assert _is_icmp_block(3, 1) is True  # host unreachable
    assert _is_icmp_block(3, 9) is True  # net administratively prohibited
    assert _is_icmp_block(3, 10) is True  # host administratively prohibited
    assert _is_icmp_block(3, 3) is False  # port unreachable (not block)
    assert _is_icmp_block(11, 0) is False  # TTL exceeded


@pytest.mark.unit
def test_icmp_parse_ipv4_packet():
    # IPv4 header (20B) + ICMP type=3 code=13
    pkt = bytes([0x45]) + bytes(19) + bytes([3, 13]) + bytes(8)
    t, c = _parse_icmp(pkt)
    assert (t, c) == (3, 13)


@pytest.mark.unit
def test_icmp_parse_bare():
    # bare ICMP (type=3, code=13) without IP header — 8 bytes minimum
    t, c = _parse_icmp(bytes([3, 13, 0, 0, 0, 0, 0, 0]))
    assert (t, c) == (3, 13)


@pytest.mark.unit
def test_icmp_parse_too_short():
    assert _parse_icmp(bytes([3, 13, 0, 0])) == (None, None)


@pytest.mark.unit
def test_l3_probe_reachable_ip(monkeypatch):
    import contextlib

    monkeypatch.setattr(
        "blockchecks.checkers.l3_probe.socket.create_connection",
        lambda *a, **k: contextlib.nullcontext(),
    )
    r = probe_l3("8.8.8.8", 443, timeout=2, use_raw=False)
    assert r.phase == FailPhase.PASS
    assert r.tcp_reachable is True


@pytest.mark.unit
def test_l3_probe_silent_drop_doc_ip(monkeypatch):
    def _timeout(*a, **k):
        raise TimeoutError("connect timed out")

    monkeypatch.setattr("blockchecks.checkers.l3_probe.socket.create_connection", _timeout)
    r = probe_l3("192.0.2.1", 443, timeout=1.5, use_raw=False)
    assert r.phase == FailPhase.L4_SYN_DROP


@pytest.mark.unit
def test_l3_raw_unknown_falls_back_to_connect(monkeypatch):
    import contextlib

    monkeypatch.setattr(
        "blockchecks.checkers.l3_probe._probe_l3_raw",
        lambda res, _timeout: res,
    )
    monkeypatch.setattr(
        "blockchecks.checkers.l3_probe.socket.create_connection",
        lambda *_a, **_k: contextlib.nullcontext(),
    )
    r = probe_l3("8.8.8.8", 443, timeout=2, use_raw=True)
    assert r.phase == FailPhase.PASS
    assert r.tcp_reachable is True


@pytest.mark.unit
def test_l3_raw_icmp_block_skips_tcp(monkeypatch):
    def _icmp(res, _timeout):
        res.phase = FailPhase.ICMP_BLOCK
        return res

    def _no_tcp(*_a, **_k):
        raise AssertionError("TCP fallback must not run after ICMP block")

    monkeypatch.setattr("blockchecks.checkers.l3_probe._probe_l3_raw", _icmp)
    monkeypatch.setattr("blockchecks.checkers.l3_probe.socket.create_connection", _no_tcp)
    r = probe_l3("192.0.2.1", 443, timeout=1, use_raw=True)
    assert r.phase == FailPhase.ICMP_BLOCK


@pytest.mark.unit
def test_l3_probe_connection_refused(monkeypatch):
    def _refused(*a, **k):
        raise OSError(errno.ECONNREFUSED, "Connection refused")

    monkeypatch.setattr("blockchecks.checkers.l3_probe.socket.create_connection", _refused)
    r = probe_l3("192.0.2.1", 443, timeout=1, use_raw=False)
    assert r.phase == FailPhase.CONNECT_REFUSED
    assert r.rst_received is False


@pytest.mark.unit
def test_l3_probe_rst_at_syn(monkeypatch):
    def _reset(*a, **k):
        raise OSError("Connection reset by peer")

    monkeypatch.setattr("blockchecks.checkers.l3_probe.socket.create_connection", _reset)
    r = probe_l3("192.0.2.1", 443, timeout=1, use_raw=False)
    assert r.phase == FailPhase.L4_RST_AT_SYN
    assert r.rst_received is True


@pytest.mark.unit
def test_l3_probe_result_to_dict():
    r = L3ProbeResult(ip="1.2.3.4", port=443, phase=FailPhase.ICMP_BLOCK)
    d = r.to_dict()
    assert d["phase"] == "icmp_block"
    assert d["ip"] == "1.2.3.4"
