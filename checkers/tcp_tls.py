"""TCP TLS connectivity checker via curl_cffi (Chrome impersonation)."""

import time
from dataclasses import dataclass
from typing import Optional

import curl_cffi


@dataclass
class TlsResult:
    domain: str
    success: bool = False
    http_status: int = 0
    latency_ms: float = 0.0
    error: Optional[str] = None
    protocol: str = ""


def check_tls(domain: str, timeout: float = 3.0,
              impersonate: str = "chrome124",
              http_version: int = 2) -> TlsResult:
    """Test TLS connectivity to a domain via curl_cffi.

    Uses Chrome 124 BoringSSL fingerprint (JA4 t13d1516h2) — browser-identical.
    """
    result = TlsResult(domain=domain)
    start = time.perf_counter()

    try:
        resp = curl_cffi.get(
            f"https://{domain}",
            impersonate=impersonate,
            http_version=http_version,
            timeout=timeout,
            headers={"Accept": "text/html"},
        )
        result.success = 200 <= resp.status_code < 400
        result.http_status = resp.status_code
        result.protocol = getattr(resp, "version", "").name if hasattr(resp, "version") else ""
    except curl_cffi.CurlError as e:
        error_msg = str(e)
        if "Timeout" in error_msg:
            result.error = "timeout"
        elif "reset" in error_msg.lower():
            result.error = "connection reset"
        elif "SSL" in error_msg or "TLS" in error_msg:
            result.error = "TLS error"
        else:
            result.error = error_msg[:120]
    except Exception as e:
        result.error = str(e)[:120]

    result.latency_ms = (time.perf_counter() - start) * 1000
    return result
