"""Connectivity probes: TLS, HTTP, QUIC, UDP voice, DNS, and IP/port checks."""

from blockchecks.checkers.tcp_tls import TlsResult, check_tls

__all__ = ["TlsResult", "check_tls"]
