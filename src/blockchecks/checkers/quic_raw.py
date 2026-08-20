"""Raw QUIC Initial drop probe (Triage Phase 5).

Sends a real QUIC Initial packet (from the baked ``quic_initial*.bin`` blob, or
a synthetic RFC 9000 Initial as fallback) over UDP :443 and classifies:
- ``PASS`` — server replied (Initial/Handshake/Retry packet) → QUIC path open.
- ``QUIC_DROP`` — no response (TSPU drops QUIC Initial by SNI).
- ``UDP_BLOCKED`` — ICMP Port Unreachable / admin-prohibited.

Distinct from ``check_http3`` (full HTTP/3 via curl) — this is a raw one-shot
probe used by preflight to build the ``TriageProfile.quic_drop`` flag.
"""

from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass
from pathlib import Path

from blockchecks.engine.fail_phase import FailPhase

# Baked QUIC Initial blobs (prefer a real ClientHello for realistic DPI trigger).
_QUIC_BLOB_CANDIDATES = (
    Path("/opt/zapret2/blobs/quic_initial_www_google_com.bin"),
    Path("/opt/zapret2/blobs/quic_initial.bin"),
    Path("/opt/zapret2/blobs/quic_initial_dbankcloud_ru.bin"),
)

_ICMP_DEST_UNREACH = 3
_ICMP_PORT_UNREACH = 3  # code 3 = port unreachable (typical for UDP-blocked)
_ICMP_ADMIN_PROHIBIT = 13


@dataclass
class QuicRawResult:
    ip: str
    port: int
    phase: FailPhase = FailPhase.UNKNOWN
    response_received: bool = False
    icmp_port_unreachable: bool = False
    blob_used: str = ""
    latency_ms: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "phase": self.phase.value,
            "response_received": self.response_received,
            "icmp_port_unreachable": self.icmp_port_unreachable,
            "blob_used": self.blob_used,
            "latency_ms": round(self.latency_ms, 1),
            "error": self.error,
        }


def load_quic_initial() -> tuple[bytes, str]:
    """Return (packet, source_name) — real blob first, synthetic RFC 9000 fallback."""
    for path in _QUIC_BLOB_CANDIDATES:
        if path.is_file():
            data = path.read_bytes()
            if len(data) >= 40:
                return data, str(path.name)
    return _synthetic_rfc9000_initial(), "synthetic_rfc9000"


def _quic_varint(n: int) -> bytes:
    """RFC 9000 variable-length integer (1/2/4/8 bytes)."""
    if n < 64:
        return bytes([n])
    if n < 16384:
        return (0x4000 | n).to_bytes(2, "big")
    if n < 1_073_741_824:
        return (0x8000_0000 | n).to_bytes(4, "big")
    return (0xC000_0000_0000_0000 | n).to_bytes(8, "big")


def _synthetic_rfc9000_initial() -> bytes:
    """Build a minimal RFC 9000 QUIC Initial packet (1200B) with no crypto."""
    # Long header: form=1, fixed=1, type=Initial(00), reserved=00, PN length=1 → 0xC0
    pn_len = 1
    first = 0xC0 | (pn_len - 1)
    dcid = os.urandom(8)
    scid = b""
    token = b""
    prefix = (
        bytes([first])
        + (1).to_bytes(4, "big")
        + bytes([len(dcid)])
        + dcid
        + bytes([len(scid)])
        + scid
        + _quic_varint(len(token))
        + token
    )
    length_field_size = 2  # 2-byte varint for Length in 64..16383
    payload_len = 1200 - len(prefix) - length_field_size - pn_len
    length_field = _quic_varint(pn_len + payload_len)
    return prefix + length_field + os.urandom(pn_len) + os.urandom(payload_len)


def _parse_icmp(pkt: bytes) -> tuple[int | None, int | None]:
    """Parse ICMP header from a raw IPv4 packet (may include IP header)."""
    if len(pkt) < 8:
        return None, None
    if pkt[0] >> 4 == 4 and len(pkt) >= 20:
        ihl = (pkt[0] & 0x0F) * 4
        pkt = pkt[ihl:]
    if len(pkt) < 4:
        return None, None
    return pkt[0], pkt[1]


def probe_quic_initial(
    ip: str,
    port: int = 443,
    timeout: float = 3.0,
    *,
    blob: bytes | None = None,
    blob_name: str = "",
) -> QuicRawResult:
    """One-shot raw QUIC Initial probe over UDP :443."""
    t0 = time.perf_counter()
    res = QuicRawResult(ip=ip, port=port)

    packet, used = (blob, blob_name) if blob else load_quic_initial()
    res.blob_used = used

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    icmp: socket.socket | None = None
    try:
        udp.settimeout(timeout)
        udp.sendto(packet, (ip, port))
        # ICMP receiver for Port Unreachable (best-effort; raw needs CAP_NET_RAW).
        try:
            icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmp.settimeout(timeout)
        except (OSError, PermissionError):
            icmp = None

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(deadline - time.monotonic(), 0.001)
            udp.settimeout(remaining)
            try:
                data, _addr = udp.recvfrom(2048)
                if len(data) >= 1:
                    # Any QUIC packet from server (Long/Short header) = response.
                    res.response_received = True
                    res.phase = FailPhase.PASS
                    res.latency_ms = (time.perf_counter() - t0) * 1000
                    return res
            except TimeoutError:
                # No UDP response yet — check ICMP (e.g. Port Unreachable), then loop.
                pass
            if icmp is not None:
                try:
                    pkt, _ = icmp.recvfrom(4096)
                except (TimeoutError, BlockingIOError):
                    continue
                icmp_type, icmp_code = _parse_icmp(pkt)
                if icmp_type == _ICMP_DEST_UNREACH and icmp_code in (
                    _ICMP_PORT_UNREACH,
                    _ICMP_ADMIN_PROHIBIT,
                ):
                    res.icmp_port_unreachable = True
                    res.phase = FailPhase.UDP_BLOCKED
                    res.error = f"ICMP dest-unreachable code {icmp_code}"
                    res.latency_ms = (time.perf_counter() - t0) * 1000
                    return res
        # No response → TSPU dropped the QUIC Initial (silent).
        res.phase = FailPhase.QUIC_DROP
        res.error = "QUIC Initial sent, no response (dropped)"
    except OSError as e:
        res.phase = FailPhase.UDP_BLOCKED
        res.error = str(e)[:120]
    finally:
        udp.close()
        if icmp is not None:
            icmp.close()
    res.latency_ms = (time.perf_counter() - t0) * 1000
    return res
