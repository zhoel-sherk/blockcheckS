"""Raw QUIC Initial probe tests (Phase 5) — mocked sockets."""

from __future__ import annotations

import socket
from pathlib import Path
from unittest.mock import patch

import pytest

from blockchecks.checkers.quic_raw import (
    QuicRawResult,
    _parse_icmp,
    _synthetic_rfc9000_initial,
    probe_quic_initial,
)
from blockchecks.engine.fail_phase import FailPhase


@pytest.mark.unit
def test_load_quic_initial_real_blob():
    # _QUIC_BLOB_CANDIDATES points at /opt/zapret2/blobs (absent on CI). Point
    # it at the repo blob so the real-binary parse path is exercised everywhere.
    repo_blob = Path(__file__).resolve().parents[2] / "blobs" / "quic_initial_www_google_com.bin"
    if not repo_blob.is_file():
        pytest.skip("quic_initial_www_google_com.bin not in repo")
    import blockchecks.checkers.quic_raw as qr

    with patch.object(qr, "_QUIC_BLOB_CANDIDATES", (repo_blob,)):
        packet, name = qr.load_quic_initial()
    assert len(packet) >= 40
    assert packet[0] & 0x80  # LONG header
    assert name.endswith(".bin")


@pytest.mark.unit
def test_synthetic_rfc9000_initial():
    pkt = _synthetic_rfc9000_initial()
    assert len(pkt) == 1200
    assert pkt[0] & 0x80  # LONG header form
    assert pkt[0] & 0x40  # fixed bit
    assert (pkt[0] & 0x30) == 0  # Initial
    assert (pkt[0] & 0x03) == 0  # 1-byte packet number
    assert pkt[1:5] == b"\x00\x00\x00\x01"  # QUIC v1
    # Length is a 2-byte varint (high bits 01) covering PN + payload
    dcid_len = pkt[5]
    length_off = 1 + 4 + 1 + dcid_len + 1 + 0 + 1  # token_len varint of 0
    length_bytes = pkt[length_off : length_off + 2]
    assert length_bytes[0] & 0xC0 == 0x40
    length = ((length_bytes[0] & 0x3F) << 8) | length_bytes[1]
    assert length == 1200 - length_off - 2


@pytest.mark.unit
def test_parse_icmp_ipv4_packet():
    pkt = bytes([0x45]) + bytes(19) + bytes([3, 3, 0, 0]) + bytes(4)
    t, c = _parse_icmp(pkt)
    assert (t, c) == (3, 3)


@pytest.mark.unit
def test_probe_quic_pass(monkeypatch):
    class FakeUdp:
        def __init__(self, *a, **k):
            self.settimeout_calls = 0

        def settimeout(self, t):
            self.settimeout_calls += 1

        def sendto(self, *a):
            pass

        def recvfrom(self, n):
            # simulate server QUIC response
            return b"\xc0\x00\x00\x00\x01" + b"\x00" * 64, ("1.2.3.4", 443)

        def close(self):
            pass

    class FakeIcmp:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, t):
            pass

        def recvfrom(self, n):
            raise TimeoutError

        def close(self):
            pass

    monkeypatch.setattr(
        "blockchecks.checkers.quic_raw.socket.socket",
        lambda *a, **k: FakeUdp() if a and a[1] == socket.SOCK_DGRAM else FakeIcmp(),
    )
    r = probe_quic_initial("1.2.3.4", 443, timeout=2, blob=b"x" * 1200, blob_name="test")
    assert r.phase == FailPhase.PASS
    assert r.response_received is True


@pytest.mark.unit
def test_probe_quic_drop(monkeypatch):
    class FakeUdp:
        def settimeout(self, t):
            pass

        def sendto(self, *a):
            pass

        def recvfrom(self, n):
            raise TimeoutError

        def close(self):
            pass

    class FakeIcmp:
        def settimeout(self, t):
            pass

        def recvfrom(self, n):
            raise TimeoutError

        def close(self):
            pass

    monkeypatch.setattr(
        "blockchecks.checkers.quic_raw.socket.socket",
        lambda *a, **k: FakeUdp() if a and a[1] == socket.SOCK_DGRAM else FakeIcmp(),
    )
    r = probe_quic_initial("1.2.3.4", 443, timeout=1, blob=b"x" * 1200, blob_name="test")
    assert r.phase == FailPhase.QUIC_DROP


@pytest.mark.unit
def test_probe_quic_icmp_port_unreachable(monkeypatch):
    class FakeUdp:
        def settimeout(self, t):
            pass

        def sendto(self, *a):
            pass

        def recvfrom(self, n):
            raise TimeoutError

        def close(self):
            pass

    class FakeIcmp:
        def settimeout(self, t):
            pass

        def recvfrom(self, n):
            # ICMP Dest Unreachable (Type 3, Code 3 = port unreachable) in IPv4 packet
            return bytes([0x45]) + bytes(19) + bytes([3, 3]) + bytes(10), ("8.8.8.8", 0)

        def close(self):
            pass

    monkeypatch.setattr(
        "blockchecks.checkers.quic_raw.socket.socket",
        lambda *a, **k: FakeUdp() if a and a[1] == socket.SOCK_DGRAM else FakeIcmp(),
    )
    r = probe_quic_initial("1.2.3.4", 443, timeout=2, blob=b"x" * 1200, blob_name="test")
    assert r.phase == FailPhase.UDP_BLOCKED
    assert r.icmp_port_unreachable is True


@pytest.mark.unit
def test_quic_raw_result_to_dict():
    r = QuicRawResult(ip="1.2.3.4", port=443, phase=FailPhase.QUIC_DROP, blob_used="q.bin")
    d = r.to_dict()
    assert d["phase"] == "quic_drop"
    assert d["blob_used"] == "q.bin"
