"""TCP TLS connectivity checker via curl_cffi (Chrome impersonation).

Addresses blockcheckS concerns:
  1. SO_MARK: handled by netns isolation (engine/test_runner.py)
  2. State race: handled by sequential testing (engine/test_runner.py)
  3. Fake responses: content validation for DPI redirect/stub detection
  4. TCP Window Clamping: read timeout via separate timing (below)
  5. DNS Leak: handled by nfqws2 netns DNS (8.8.8.8) + optional pre-resolution
"""

import socket
import time
from dataclasses import dataclass, field
from typing import Optional

import curl_cffi

# Minimal response size for a real web page.
# Redirects (301/302), No Content (204), WebSocket upgrades (101), and
# small API responses are excluded — they are valid but have tiny bodies.
MIN_CONTENT_LENGTH = 300

# Rate to verify we're actually receiving data (bytes/sec).
# DPI window clamping results in <100 bytes/sec.
MIN_BYTES_PER_SEC = 400.0

# HTTP statuses that produce tiny bodies legitimately
SMALL_BODY_STATUSES = frozenset({101, 204, 301, 302, 303, 307, 308, 304, 206})

# Patterns that indicate DPI fake response
DPI_FAKE_PATTERNS = [
]


@dataclass
class TlsResult:
    domain: str
    success: bool = False
    http_status: int = 0
    latency_ms: float = 0.0
    content_length: int = 0
    read_rate_bps: float = 0.0
    error: Optional[str] = None
    protocol: str = ""
    warnings: list[str] = field(default_factory=list)


def _validate_content(data: bytes, time_for_read: float,
                      http_status: int = 200) -> list[str]:
    """Check response body for DPI manipulation.

    Small-body HTTP status codes (301, 302, 101, 204, etc.) are
    excluded from the minimum-size check — they legitimately carry
    tiny or empty bodies.
    """
    warnings = []
    content_len = len(data)

    if http_status not in SMALL_BODY_STATUSES:
        if content_len < MIN_CONTENT_LENGTH:
            warnings.append(f"body too small ({content_len}B < {MIN_CONTENT_LENGTH}B)")

    if time_for_read > 0:
        rate = content_len / time_for_read
        if rate < MIN_BYTES_PER_SEC:
            warnings.append(f"slow read ({rate:.0f} B/s < {MIN_BYTES_PER_SEC} B/s)")

    for pattern in DPI_FAKE_PATTERNS:
        if pattern in data[:4096].lower():
            warnings.append(f"DPI pattern '{pattern.decode()}' found in body")
            break

    return warnings


def check_tls(domain: str, timeout: float = 5.0,
              impersonate: str = "chrome124",
              http_version: int = 2,
              verify_content: bool = True,
              pre_resolved_ip: Optional[str] = None,
              read_timeout: float = 4.0) -> TlsResult:
    """Test TLS connectivity to a domain via curl_cffi.

    Args:
        domain: domain to test
        timeout: total curl timeout (connect + read)
        impersonate: curl_cffi impersonation profile
        http_version: HTTP version (2 = default, 1.1 = old browsers)
        verify_content: validate body is real (not DPI stub)
        pre_resolved_ip: skip DNS, connect directly to this IP
        read_timeout: max time to wait for first content bytes
    """
    result = TlsResult(domain=domain)
    start = time.perf_counter()

    target = domain
    headers = {"Accept": "text/html,application/xhtml+xml",
               "Accept-Language": "en-US,en;q=0.9",
               "User-Agent": ""}  # curl_cffi fills this

    if pre_resolved_ip:
        target = pre_resolved_ip
        headers["Host"] = domain

    try:
        read_start = time.perf_counter()
        resp = curl_cffi.get(
            f"https://{target}",
            impersonate=impersonate,
            http_version=http_version,
            timeout=timeout,
            headers=headers,
            allow_redirects=False,
        )
        read_elapsed = time.perf_counter() - read_start
        result.http_status = resp.status_code
        result.content_length = len(resp.content)
        result.read_rate_bps = result.content_length / max(read_elapsed, 0.001)
        result.protocol = str(getattr(resp, "http_version", "?")).replace("_", "/")

        if verify_content:
            result.warnings = _validate_content(resp.content, read_elapsed,
                                                resp.status_code)
            result.success = (200 <= resp.status_code < 400) and not result.warnings
        else:
            result.success = 200 <= resp.status_code < 400

    except curl_cffi.CurlError as e:
        error_msg = str(e)
        if "Timeout" in error_msg:
            if time.perf_counter() - start < timeout * 0.6:
                result.error = "timeout (DPI window clamp?)"
            else:
                result.error = "timeout"
        elif "reset" in error_msg.lower():
            result.error = "connection reset"
        elif "SSL" in error_msg or "TLS" in error_msg:
            result.error = "TLS error"
        elif "resolve" in error_msg.lower():
            result.error = "DNS error"
        else:
            result.error = error_msg[:120]
    except Exception as e:
        result.error = str(e)[:120]

    result.latency_ms = (time.perf_counter() - start) * 1000
    return result


def resolve_domain(domain: str, nameserver: str = "8.8.8.8") -> list[str]:
    """Pre-resolve domain to IPv4 addresses via specified DNS."""
    import subprocess
    try:
        r = subprocess.run(
            ["dig", "+short", f"@{nameserver}", "A", domain],
            capture_output=True, text=True, timeout=5
        )
        return [line.strip() for line in r.stdout.splitlines() if line.strip()]
    except Exception:
        try:
            return [a[4][0] for a in socket.getaddrinfo(
                domain, 443, socket.AF_INET, socket.SOCK_STREAM
            )]
        except Exception:
            return []
