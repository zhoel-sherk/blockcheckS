"""Structured DPI failure-phase taxonomy (TriageProfile feedback).

Single source of truth for *why* a probe failed. Feeds the online bandit and
the S0 offline ranker without parsing raw curl/log strings, and drives
strategy-generator pruning (``TriageProfile``).

Every token is a stable string so it round-trips through SQLite and JSON.
HTTP status codes map dynamically to ``http_<code>`` members (e.g. ``http_403``).
"""

from __future__ import annotations

import re
from enum import Enum


class FailPhase(str, Enum):
    """Coarse DPI / network failure phase for a probe (stable tokens)."""

    UNKNOWN = "unknown"
    OTHER = "other"
    PASS = "pass"

    # Phase 1 — L3/L4 / DNS
    DNS_RESOLVE = "dns_resolve"
    DNS_TAMPERED = "dns_tampered"
    DNS_SINKHOLE = "dns_sinkhole"
    L4_SYN_DROP = "l4_syn_drop"
    L4_RST_AT_SYN = "l4_rst_at_syn"
    ICMP_BLOCK = "icmp_block"
    IP_BLOCKED = "ip_blocked"

    # Phase 2 — handshake / early DPI interception
    TLS_RST_AT_SNI = "tls_rst_at_sni"
    TLS_SILENT_DROP_AFTER_SNI = "tls_silent_drop_after_sni"
    TLS_FAKE_ALERT = "tls_fake_alert"
    TLS_HANDSHAKE_ERROR = "tls_handshake_error"
    CONNECT_TIMEOUT = "connect_timeout"
    CONNECT_REFUSED = "connect_refused"

    # Phase 3 — deep stream / data transfer failure modes
    DATA_STALL_TLS_CERT = "data_stall_tls_cert"  # Зависание на 2-5 KB (сертификат сервера)
    DATA_STALL_FIRST_REQ = "data_stall_first_req"  # Зависание после первого Application Data
    DATA_STALL_7K = "data_stall_7k"  # Ранний стрим-чек
    DATA_STALL_16K = "data_stall_16k"  # Стандартный буфер ТСПУ
    DATA_STALL_42K = "data_stall_42k"  # Расширенный буфер
    DATA_STALL_64K_PLUS = "data_stall_64k_plus"  # Переполнение TCP Reassembly ring-buffer

    # Active DPI injections during stream
    DELAYED_RST = "delayed_rst"  # RST после начала полезных данных
    DELAYED_FIN = "delayed_fin"  # Фальшивый FIN/FIN-ACK от middlebox
    TLS_INJECTED_ALERT = "tls_injected_alert"  # Внедрение Fatal TLS Alert фрейма
    ZERO_WINDOW_STALL = "zero_window_stall"  # Заморозка через TCP Window Size = 0
    H2_RST_STREAM = "h2_rst_stream"  # L7 HTTP/2 фрейм сброса потока

    # Phase 4 — QoS throttling
    BANDWIDTH_THROTTLED = "bandwidth_throttled"

    # Phase 5 — UDP / QUIC
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
    (FailPhase.DATA_STALL_7K, re.compile(r"stall.*7|stalled at 7", re.I)),
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


_PASS_HTTP = frozenset({200, 204, 206})


def classify_fail_phase(error: str, http_code: int = 0) -> FailPhase:
    """Map a probe error string to a structured failure phase.

    Empty error with 200/204/206 → PASS; other HTTP → ``http_<code>``.
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
