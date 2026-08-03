"""HTTP/3 (QUIC) connectivity checker — BC2-10."""

from __future__ import annotations

import time
from dataclasses import dataclass

import curl_cffi
from curl_cffi.requests import RequestsError

from blockchecks.checkers.tcp_tls import classify_http_status

_HTTP3_PROBE_URL = "https://cloudflare.com"


@dataclass
class Http3Result:
    domain: str
    success: bool = False
    http_status: int = 0
    latency_ms: float = 0.0
    content_length: int = 0
    error: str | None = None
    http_version: str = ""


def _classify_http3_error(msg: str) -> str:
    low = msg.lower()
    rules: tuple[tuple[bool, str], ...] = (
        ("unknown" in low or "not supported" in low, "http3 not supported by curl"),
        ("timeout" in low, "timeout"),
        ("quic" in low or "http/3" in low, msg[:120]),
    )
    return next((label for pred, label in rules if pred), msg[:120])


def supports_http3() -> bool:
    """Return True if curl_cffi can request HTTP/3 (blockcheck2 curl_supports_http3)."""
    try:
        with curl_cffi.Session(http_version="v3only", allow_redirects=False) as session:
            session.get(_HTTP3_PROBE_URL, timeout=3)
        return True
    except RequestsError as exc:
        msg = str(exc).lower()
        if "unknown" in msg and "http" in msg:
            return False
        return "not supported" not in msg and "unrecognized" not in msg


def check_http3(
    domain: str,
    timeout: float = 8.0,
    impersonate: str = "chrome124",
    pre_resolved_ip: str | None = None,
) -> Http3Result:
    """Probe domain over HTTP/3 only (QUIC/UDP 443)."""
    result = Http3Result(domain=domain)
    start = time.perf_counter()
    headers = {"Accept": "text/html,application/xhtml+xml"}

    try:
        with curl_cffi.Session(
            impersonate=impersonate,
            http_version="v3only",
            headers=headers,
            allow_redirects=False,
        ) as session:
            if pre_resolved_ip:
                from blockchecks.checkers.dns_secure import apply_curl_resolve

                apply_curl_resolve(session, domain, pre_resolved_ip, port=443)
            resp = session.head(f"https://{domain}", timeout=timeout)
        result.http_status = resp.status_code
        result.content_length = int(resp.headers.get("Content-Length") or 0)
        result.http_version = str(getattr(resp, "http_version", "")).replace("_", "/")

        loc = resp.headers.get("Location") or resp.headers.get("location") or ""
        redirect_err = classify_http_status(domain, resp.status_code, loc)
        if redirect_err:
            result.error = redirect_err
        elif 200 <= resp.status_code < 400:
            result.success = True
        else:
            result.error = f"http {resp.status_code}"
    except RequestsError as exc:
        result.error = _classify_http3_error(str(exc))
    except Exception as exc:
        result.error = str(exc)[:120]

    result.latency_ms = (time.perf_counter() - start) * 1000
    return result
