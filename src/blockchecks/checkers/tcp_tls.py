"""TLS probe via curl_cffi Chrome impersonation.
Checks status, body size, transfer rate, and DPI stub content.
"""

import socket
import time
from dataclasses import dataclass, field

import curl_cffi
from curl_cffi.requests import RequestsError

# Minimal response size for a real web page.
# Redirects (301/302), No Content (204), WebSocket upgrades (101), and
# small API responses are excluded — they are valid but have tiny bodies.
MIN_CONTENT_LENGTH = 300

# Rate to verify we're actually receiving data (bytes/sec).
# DPI window clamping results in <100 bytes/sec.
MIN_BYTES_PER_SEC = 400.0

# HTTP statuses that produce tiny bodies legitimately
SMALL_BODY_STATUSES = frozenset({101, 204, 206, 301, 302, 303, 304, 307, 308})

# Patterns that indicate DPI fake response (TSPU stubs)
DPI_FAKE_PATTERNS = [
    b"roskomnadzor",
    b"rkn.gov.ru",
    b"blockpage",
    b"utmblock",
    b"eais",
    b"warning.rt.ru",
]

# blockcheck2 curl exit 254 — suspicious redirect / blockpage
REDIRECT_BLOCK_STATUSES = frozenset({301, 302, 307, 308})


def _apply_read_timeout(session: curl_cffi.Session, read_timeout: float) -> None:
    """Abort stalled transfers via CURLOPT_LOW_SPEED_* (seconds)."""
    if read_timeout <= 0:
        return
    session.curl.setopt(curl_cffi.CurlOpt.LOW_SPEED_LIMIT, 1)
    session.curl.setopt(curl_cffi.CurlOpt.LOW_SPEED_TIME, int(max(1, read_timeout)))


def _redirect_hostname(location: str) -> str:
    """Hostname from an absolute or protocol-relative Location (empty if relative)."""
    from urllib.parse import urlparse

    loc = location.strip()
    if not loc:
        return ""
    parsed = urlparse(loc if "://" in loc or loc.startswith("//") else "")
    return (parsed.hostname or "").lower().rstrip(".")


_DISCORD_FAMILY_APEXES = frozenset({
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discordapp.net",
    "discordcdn.com",
    "discord.media",
})


def _in_discord_family(host: str) -> bool:
    h = host.lower().rstrip(".")
    return any(h == apex or h.endswith("." + apex) for apex in _DISCORD_FAMILY_APEXES)


def _hosts_related(host: str, domain: str) -> bool:
    """True if *host* is the same site as *domain* (subdomain ↔ apex included, or brand family)."""
    h, d = host.lower().rstrip("."), domain.lower().rstrip(".")
    if not (h and d):
        return False
    if _in_discord_family(h) and _in_discord_family(d):
        return True
    return h == d or h.endswith("." + d) or d.endswith("." + h)


def is_suspicious_redirect(domain: str, status: int, location: str) -> bool:
    """Detect DPI blockpage redirects (blockcheck2 curl_test_http).

    Same-site redirects are OK, including subdomain→apex (``www.youtube.com`` →
    ``https://youtube.com/``) and protocol-relative ``//host/...`` Locations.
    Relative paths have no host and are treated as same-site.
    """
    if status not in REDIRECT_BLOCK_STATUSES or not location:
        return False
    loc_host = _redirect_hostname(location)
    if not loc_host:
        return False
    dom = domain.lower().split("/")[0].split(":")[0].rstrip(".")
    return not _hosts_related(loc_host, dom)


def classify_http_status(domain: str, status: int, location: str = "") -> str | None:
    """Return error string for suspicious HTTP codes, else None."""
    if is_suspicious_redirect(domain, status, location):
        return f"suspicious redirect {status} to {location[:80]}"
    if status == 400:
        return "http 400 (likely fake packets received)"
    return None


@dataclass
class TlsResult:
    domain: str
    success: bool = False
    http_status: int = 0
    latency_ms: float = 0.0
    content_length: int = 0
    read_rate_bps: float = 0.0
    error: str | None = None
    protocol: str = ""
    warnings: list[str] = field(default_factory=list)


def _validate_content(data: bytes, time_for_read: float, http_status: int = 200) -> list[str]:
    """Check response body for DPI manipulation.

    Small-body HTTP status codes (301, 302, 101, 204, etc.) and TLS bypass-proof
    statuses (401, 403, 404) are excluded from the minimum-size check.
    """
    warnings = []
    content_len = len(data)

    if (
        http_status not in SMALL_BODY_STATUSES
        and http_status not in {401, 403, 404}
        and content_len < MIN_CONTENT_LENGTH
    ):
        warnings.append(f"body too small ({content_len}B < {MIN_CONTENT_LENGTH}B)")

    if (
        time_for_read > 0
        and http_status not in SMALL_BODY_STATUSES
        and http_status not in {401, 403, 404}
    ):
        rate = content_len / time_for_read
        if rate < MIN_BYTES_PER_SEC:
            warnings.append(f"slow read ({rate:.0f} B/s < {MIN_BYTES_PER_SEC} B/s)")

    for pattern in DPI_FAKE_PATTERNS:
        if pattern in data[:4096].lower():
            warnings.append(f"DPI pattern '{pattern.decode()}' found in body")
            break

    return warnings


def _classify_tls_error(msg: str, *, elapsed: float, timeout: float) -> str:
    """Map curl_cffi transport errors to short tls probe labels."""
    low = msg.lower()
    rules: tuple[tuple[bool, str], ...] = (
        ("Timeout" in msg and elapsed < timeout * 0.6, "timeout (DPI window clamp?)"),
        ("Timeout" in msg, "timeout"),
        ("reset" in low, "connection reset"),
        ("ssl" in low or "tls" in low, "TLS error"),
        ("resolve" in low, "DNS error"),
    )
    return next((label for pred, label in rules if pred), msg[:120])


def check_tls(
    domain: str,
    timeout: float = 5.0,
    impersonate: str = "chrome124",
    http_version: int = 2,
    verify_content: bool = True,
    pre_resolved_ip: str | None = None,
    read_timeout: float = 4.0,
) -> TlsResult:
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

    # Omit User-Agent so curl_cffi impersonation supplies a real browser UA
    headers = {"Accept": "text/html,application/xhtml+xml", "Accept-Language": "en-US,en;q=0.9"}

    try:
        with curl_cffi.Session(
            impersonate=impersonate,
            http_version=http_version,
            headers=headers,
            allow_redirects=False,
        ) as session:
            if pre_resolved_ip:
                from blockchecks.checkers.dns_secure import apply_curl_resolve

                apply_curl_resolve(session, domain, pre_resolved_ip)
            _apply_read_timeout(session, read_timeout)
            read_start = time.perf_counter()
            resp = session.get(f"https://{domain}", timeout=timeout)
        read_elapsed = time.perf_counter() - read_start
        result.http_status = resp.status_code
        result.content_length = len(resp.content)
        result.read_rate_bps = result.content_length / max(read_elapsed, 0.001)
        result.protocol = str(getattr(resp, "http_version", "?")).replace("_", "/")

        loc = resp.headers.get("Location") or resp.headers.get("location") or ""
        redirect_err = classify_http_status(domain, resp.status_code, loc)
        if redirect_err:
            result.error = redirect_err
            result.success = False
        elif verify_content:
            result.warnings = _validate_content(resp.content, read_elapsed, resp.status_code)
            result.success = (
                (200 <= resp.status_code < 400 or resp.status_code in {401, 403, 404})
                and not result.warnings
            )
        else:
            result.success = (
                200 <= resp.status_code < 400 or resp.status_code in {401, 403, 404}
            )

    except RequestsError as e:
        result.error = _classify_tls_error(
            str(e), elapsed=time.perf_counter() - start, timeout=timeout
        )
    except Exception as e:
        result.error = str(e)[:120]

    result.latency_ms = (time.perf_counter() - start) * 1000
    return result


def resolve_domain(domain: str, nameserver: str | None = None) -> list[str]:
    """Pre-resolve domain to IPv4 addresses via specified DNS."""
    import subprocess

    from blockchecks.engine.config import first_udp_nameserver

    ns = nameserver or first_udp_nameserver()

    try:
        r = subprocess.run(
            ["dig", "+short", f"@{ns}", "A", domain],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return [line.strip() for line in r.stdout.splitlines() if line.strip()]
    except Exception:
        try:
            return [
                a[4][0] for a in socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
            ]
        except Exception:
            return []
