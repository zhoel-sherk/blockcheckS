"""Hop-distance estimation from observed IP TTL (preflight Tier 1)."""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass

_INITIAL_TTLS = (64, 128, 255)


@dataclass
class TtlProbeResult:
    server_ttl: int | None = None
    dpi_ttl: int | None = None
    server_hops: int | None = None
    dpi_hops: int | None = None
    autottl_delta: int | None = None
    error: str = ""


def hops_from_ttl(ttl: int) -> int:
    """Hops travelled assuming the sender started at 64 / 128 / 255."""
    if ttl <= 0:
        return 0
    initial = next((i for i in _INITIAL_TTLS if ttl <= i), ttl)
    return max(0, initial - ttl)


def autottl_delta(server_hops: int | None, dpi_hops: int | None) -> int | None:
    """nfqws2 ``ip_autottl`` delta so fakes expire at the middlebox."""
    if dpi_hops is None or dpi_hops <= 0:
        return None
    if server_hops is not None and server_hops <= dpi_hops:
        return None
    return dpi_hops


def ttl_reaches_dpi(ttl: int, dpi_hops: int | None, server_hops: int | None) -> bool:
    """True if ``ip_ttl=ttl`` still exists when it hits DPI and dies before origin."""
    if dpi_hops is not None and ttl < dpi_hops:
        return False
    return not (server_hops is not None and ttl >= server_hops)


def probe_ttl(ip: str, port: int = 443, timeout: float = 2.0) -> TtlProbeResult:
    """Read inbound SYN-ACK TTL (and RST TTL if the handshake is reset)."""
    res = TtlProbeResult()
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except (OSError, PermissionError) as e:
        res.error = f"raw socket unavailable: {e}"
        return res
    try:
        raw.settimeout(timeout)
        raw.bind(("", port))
        _nudge_syn(ip, port)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                pkt, addr = raw.recvfrom(65535)
            except TimeoutError:
                break
            if addr[0] != ip or len(pkt) < 20:
                continue
            ttl, flags = _parse_ipv4_tcp(pkt)
            if ttl is None:
                continue
            syn_ack = flags & 0x12 == 0x12
            rst = bool(flags & 0x04)
            if syn_ack and res.server_ttl is None:
                res.server_ttl = ttl
                res.server_hops = hops_from_ttl(ttl)
            elif rst and res.dpi_ttl is None:
                res.dpi_ttl = ttl
                res.dpi_hops = hops_from_ttl(ttl)
            if res.server_ttl is not None and res.dpi_ttl is not None:
                break
    finally:
        raw.close()
    res.autottl_delta = autottl_delta(res.server_hops, res.dpi_hops)
    return res


def _nudge_syn(ip: str, port: int) -> None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        s.connect_ex((ip, port))
        s.close()
    except OSError:
        pass


def _parse_ipv4_tcp(pkt: bytes) -> tuple[int | None, int]:
    if len(pkt) < 20 or pkt[0] >> 4 != 4:
        return None, 0
    ihl = (pkt[0] & 0x0F) * 4
    ttl = pkt[8]
    if len(pkt) < ihl + 14:
        return ttl, 0
    _, _, flags_off = struct.unpack("!HHH", pkt[ihl + 8 : ihl + 14])
    flags = flags_off & 0xFF  # TCP flags byte (offset 13), not data-offset
    return ttl, flags
