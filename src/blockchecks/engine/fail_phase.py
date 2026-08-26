"""Named DPI failure reasons as stable strings for SQLite and JSON.
HTTP codes become http_<code> members (for example http_403).
"""

from __future__ import annotations

import re
from enum import Enum


class FailPhase(str, Enum):
    """Coarse DPI / network failure phase for a probe (stable tokens)."""

    UNKNOWN = "unknown"
    OTHER = "other"
    PASS = "pass"

    # L3 / L4 / DNS
    DNS_RESOLVE = "dns_resolve"
    DNS_TAMPERED = "dns_tampered"
    DNS_SINKHOLE = "dns_sinkhole"
    L4_SYN_DROP = "l4_syn_drop"
    L4_RST_AT_SYN = "l4_rst_at_syn"
    ICMP_BLOCK = "icmp_block"
    IP_BLOCKED = "ip_blocked"

    # Handshake / early DPI
    TLS_RST_AT_SNI = "tls_rst_at_sni"
    TLS_SILENT_DROP_AFTER_SNI = "tls_silent_drop_after_sni"
    TLS_FAKE_ALERT = "tls_fake_alert"
    TLS_HANDSHAKE_ERROR = "tls_handshake_error"
    CONNECT_TIMEOUT = "connect_timeout"
    CONNECT_REFUSED = "connect_refused"

    # Stream / data transfer
    DATA_STALL_TLS_CERT = "data_stall_tls_cert"  # stall at 2-5 KB (server cert)
    DATA_STALL_FIRST_REQ = "data_stall_first_req"  # stall after first Application Data
    DATA_STALL_7K = "data_stall_7k"  # stall near 7 KB
    DATA_STALL_16K = "data_stall_16k"  # stall near 16 KB (common TSPU buffer)
    DATA_STALL_42K = "data_stall_42k"  # stall near 42 KB
    DATA_STALL_64K_PLUS = "data_stall_64k_plus"  # stall past 64 KB (TCP reassembly)

    # Active DPI injections during stream
    DELAYED_RST = "delayed_rst"  # RST after payload started
    DELAYED_FIN = "delayed_fin"  # FIN/FIN-ACK from a middlebox
    TLS_INJECTED_ALERT = "tls_injected_alert"  # injected Fatal TLS Alert
    ZERO_WINDOW_STALL = "zero_window_stall"  # TCP window size 0
    H2_RST_STREAM = "h2_rst_stream"  # HTTP/2 RST_STREAM

    # QoS throttling
    BANDWIDTH_THROTTLED = "bandwidth_throttled"

    # UDP / QUIC
    QUIC_DROP = "quic_drop"
    UDP_BLOCKED = "udp_blocked"

    # HTTP-visible
    HTTP_REDIRECT = "http_redirect"
    HTTP_BLOCKED = "http_blocked"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def _missing_(cls, value):
        # Dynamic http_<code> members (http_302 … http_599) for structured
        # feedback — created lazily, cached in the member map.
        if isinstance(value, str) and re.fullmatch(r"http_[3-5]\d\d", value):
            member = str.__new__(cls, value)
            member._name_ = "HTTP_" + value.split("_")[1]
            member._value_ = value
            cls._value2member_map_[value] = member
            return member
        return None


def http_phase(code: int) -> FailPhase:
    """Return the FailPhase for an HTTP status code (dynamic member)."""
    key = f"http_{int(code)}"
    return FailPhase(key)


_PHASE_PATTERNS: tuple[tuple[FailPhase, re.Pattern], ...] = (
    # Specific stream/injection phases FIRST so broad patterns don't shadow them.
    (FailPhase.ZERO_WINDOW_STALL, re.compile(r"zero window|window=0|rwnd", re.I)),
    (FailPhase.H2_RST_STREAM, re.compile(r"http/2.*rst|h2.*stream|RST_STREAM", re.I)),
    (FailPhase.TLS_INJECTED_ALERT, re.compile(r"tls alert|fatal.*alert|alert.*fatal", re.I)),
    (FailPhase.DATA_STALL_64K_PLUS, re.compile(r"stall.*64|stalled at 64|reassembly", re.I)),
    (FailPhase.DATA_STALL_42K, re.compile(r"stall.*42|stalled at 42", re.I)),
    (FailPhase.DATA_STALL_16K, re.compile(r"stall.*16|stalled at 16", re.I)),
    (
        FailPhase.DATA_STALL_7K,
        re.compile(r"stall.*\b7k\b|\b7kb\b|stalled at 7(?!\d)|stall.*[^0-9]7(?!\d)k?", re.I),
    ),
    (FailPhase.DATA_STALL_FIRST_REQ, re.compile(r"stall.*first|stalled at first|first req", re.I)),
    (FailPhase.DATA_STALL_TLS_CERT, re.compile(r"stall.*cert|cert.*stall|stalled at 2", re.I)),
    (FailPhase.DELAYED_RST, re.compile(r"reset after|rst after", re.I)),
    (FailPhase.DELAYED_FIN, re.compile(r"fin after|fin_ack|fake fin", re.I)),
    (FailPhase.DNS_RESOLVE, re.compile(r"Could not resolve|Failed to resolve|getaddrinfo", re.I)),
    (FailPhase.DNS_TAMPERED, re.compile(r"TAMPERED|dns.*mismatch", re.I)),
    (
        FailPhase.DNS_SINKHOLE,
        re.compile(r"sinkhole|bogon|reserved ip|198\.18\.|127\.0\.0\.1", re.I),
    ),
    (FailPhase.CONNECT_TIMEOUT, re.compile(r"timed? ?out|timeout after|Operation timed out", re.I)),
    (FailPhase.CONNECT_REFUSED, re.compile(r"Connection refused|ECONNREFUSED", re.I)),
    (
        FailPhase.TLS_RST_AT_SNI,
        re.compile(r"Recv failure|Connection reset|ECONNRESET|\bTCP RST\b", re.I),
    ),
    (FailPhase.TLS_SILENT_DROP_AFTER_SNI, re.compile(r"no data|silent|frozen|stalled", re.I)),
    (
        FailPhase.TLS_HANDSHAKE_ERROR,
        re.compile(r"SSL routines|WRONG_VERSION|TLS|handshake", re.I),
    ),
    (FailPhase.HTTP_REDIRECT, re.compile(r"suspicious redirect", re.I)),
    (FailPhase.HTTP_BLOCKED, re.compile(r"403|451|captcha|blocked", re.I)),
    (FailPhase.IP_BLOCKED, re.compile(r"IP.*block|blacklist|110\b", re.I)),
)


# TLS handshake to origin (empty/small 401/403/404) is a Fryazino bypass proof.
_PASS_HTTP = frozenset({200, 204, 206, 401, 403, 404})


def classify_fail_phase(error: str, http_code: int = 0) -> FailPhase:
    """Map a probe error string to a structured failure phase.

    Empty error with 200/204/206 or TLS-bypass 401/403/404 → PASS; other HTTP → ``http_<code>``.
    """
    if not error:
        if http_code in _PASS_HTTP:
            return FailPhase.PASS
        if http_code:
            return http_phase(http_code)
        return FailPhase.UNKNOWN
    for phase, pat in _PHASE_PATTERNS:
        if pat.search(error):
            return phase
    return FailPhase.OTHER
