"""Classify L3/L4 blackholes: silent SYN drop, RST-at-SYN, ICMP unreachable.
Uses a raw ICMP receiver when possible; otherwise TCP connect.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from blockchecks.engine.fail_phase import FailPhase


@dataclass
class L3ProbeResult:
    ip: str
    port: int
    phase: FailPhase = FailPhase.UNKNOWN
    tcp_reachable: bool = False
    syn_ack_received: bool = False
    rst_received: bool = False
    icmp_type: int | None = None
    icmp_code: int | None = None
    latency_ms: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "phase": self.phase.value,
            "tcp_reachable": self.tcp_reachable,
            "syn_ack_received": self.syn_ack_received,
            "rst_received": self.rst_received,
            "icmp_type": self.icmp_type,
            "icmp_code": self.icmp_code,
            "latency_ms": round(self.latency_ms, 1),
            "error": self.error,
        }


_ICMP_DEST_UNREACH = 3
# Codes that indicate the destination itself is filtered/blackholed.
_ICMP_FILTER_CODES = {1, 9, 10, 13}
_ICMP_ADMIN_PROHIBIT = 13


def _is_icmp_block(icmp_type: int, icmp_code: int) -> bool:
    return icmp_type == _ICMP_DEST_UNREACH and (
        icmp_code == _ICMP_ADMIN_PROHIBIT or icmp_code in _ICMP_FILTER_CODES
    )


def probe_l3(
    ip: str,
    port: int = 443,
    timeout: float = 3.0,
    *,
    use_raw: bool = True,
) -> L3ProbeResult:
    """Classify L3/L4 blocking for ip:port.

    ``use_raw`` tries a raw SYN + ICMP receiver first (needs root); when the
    raw socket can't be created (no CAP_NET_RAW) it falls back to TCP connect
    classification (RST vs silent drop vs reachable).
    """
    t0 = time.perf_counter()
    res = L3ProbeResult(ip=ip, port=port)

    if use_raw:
        out = _probe_l3_raw(res, timeout)
        if out is not None:
            res = out
            res.latency_ms = (time.perf_counter() - t0) * 1000
            return res

    # Fallback: TCP connect classification.
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            res.tcp_reachable = True
            res.syn_ack_received = True
            res.phase = FailPhase.PASS
    except TimeoutError:
        res.phase = FailPhase.L4_SYN_DROP
        res.error = "SYN sent, no response (silent blackhole)"
    except OSError as e:
        msg = str(e)
        if "reset" in msg.lower() or "connection refused" in msg.lower():
            res.rst_received = True
            res.phase = FailPhase.L4_RST_AT_SYN
            res.error = msg[:120]
        else:
            res.phase = FailPhase.UNKNOWN
            res.error = msg[:120]
    res.latency_ms = (time.perf_counter() - t0) * 1000
    return res


def _probe_l3_raw(res: L3ProbeResult, timeout: float) -> L3ProbeResult | None:
    """Raw SYN probe + ICMP receiver. Returns None if raw sockets unavailable."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except (OSError, PermissionError):
        return None
    try:
        s.settimeout(timeout)
        _send_syn(res.ip, res.port)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                pkt, _addr = s.recvfrom(4096)
            except TimeoutError:
                break
            icmp_type, icmp_code = _parse_icmp(pkt)
            if icmp_type is None:
                continue
            res.icmp_type = icmp_type
            res.icmp_code = icmp_code
            if _is_icmp_block(icmp_type, icmp_code):
                res.phase = FailPhase.ICMP_BLOCK
                res.error = f"ICMP Type {icmp_type} Code {icmp_code} (filtered/blackhole)"
                return res
    finally:
        s.close()
    # No ICMP and no TCP confirmation → assume silent SYN drop if connect also
    # fails without RST; otherwise PASS via connect fallback.
    return res  # phase stays UNKNOWN; caller may fall back to connect check


def _send_syn(ip: str, port: int) -> None:
    """Best-effort raw SYN (needs CAP_NET_RAW); silently ignored on failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        s.connect_ex((ip, port))
        s.close()
    except OSError:
        pass


def _parse_icmp(pkt: bytes) -> tuple[int | None, int | None]:
    """Parse ICMP header from a raw IPv4 packet (may include IP header)."""
    if len(pkt) < 8:
        return None, None
    # raw socket returns ICMP message with IP header stripped
    if pkt[0] >> 4 == 4 and len(pkt) >= 20:
        # contains IPv4 header → skip it
        ihl = (pkt[0] & 0x0F) * 4
        pkt = pkt[ihl:]
    if len(pkt) < 4:
        return None, None
    return pkt[0], pkt[1]


def run_l3_triage(ips: list[str], port: int = 443, timeout: float = 3.0) -> list[L3ProbeResult]:
    """Probe multiple IPs; returns per-IP classification."""
    return [probe_l3(ip, port, timeout) for ip in ips]
