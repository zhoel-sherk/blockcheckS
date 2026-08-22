"""Stage-aware error tokens. Local to dpi_diag — does not patch FailPhase."""

from __future__ import annotations

import re

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("tls_mitm", re.compile(r"certificate verify|self[- ]signed|cert.*(fail|error)", re.I)),
    ("tls_spoof", re.compile(r"wrong_version_number|unexpected.?message|bad record mac", re.I)),
    ("tls_alert", re.compile(r"unrecognized.?name|handshake_failure|unknown ca", re.I)),
    ("syn_drop", re.compile(r"connect.*(timed? ?out)|timed out after \d+ milliseconds", re.I)),
    ("tls_rst", re.compile(r"connection reset|econnreset|tcp rst", re.I)),
    ("tls_drop", re.compile(r"eof|no data|operation timed out|ssl.*timeout", re.I)),
    ("cgnat", re.compile(r"100\.64\.|cgnat|shared.?address", re.I)),
)


def classify_stage(error: str, *, stage: str = "") -> str:
    """Map a transport/SSL error (+ optional httpx-style stage) to a token."""
    blob = f"{stage} {error}".strip()
    if not blob:
        return "ok"
    if stage == "tcp_connect":
        return "syn_drop"
    if stage == "tls_handshake" and not error:
        return "tls_drop"
    return next((tok for tok, pat in _PATTERNS if pat.search(blob)), "other")
