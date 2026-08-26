"""HTTP/3 (QUIC) connectivity probe via curl."""

from __future__ import annotations

import json
import subprocess as sp
import time
from dataclasses import dataclass

import curl_cffi
from curl_cffi.requests import RequestsError

from blockchecks.checkers.tcp_tls import classify_http_status
from blockchecks.engine.config import HTTP3_TIMEOUT

_HTTP3_PROBE_URL = "https://cloudflare.com"

_QUIC_FAIL = {
    "success": False,
    "http_code": 0,
    "latency_ms": 0,
    "content_len": 0,
    "content_ok": False,
    "throttled": False,
    "read_rate_bps": 0,
}


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
            session.get(_HTTP3_PROBE_URL, timeout=HTTP3_TIMEOUT)
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


def http3_result_dict(result: Http3Result, *, resolve_name: str | None = None) -> dict:
    """Map Http3Result to the probe result dict shared by classic and bridge paths."""
    return {
        "resolve_name": resolve_name if resolve_name is not None else result.domain.split("/")[0],
        "success": result.success,
        "http_code": result.http_status,
        "latency_ms": result.latency_ms,
        "content_len": result.content_length,
        "content_ok": True,
        "throttled": False,
        "read_rate_bps": 0,
        "error": result.error,
        "http_version": result.http_version,
    }


def quic_subprocess_result(
    ns_name: str,
    python_bin: str,
    domain: str,
    timeout: float,
    pre_resolved_ip: str | None = None,
) -> dict:
    """Run check_http3 inside a netns via ``python -c``; unified error mapping."""
    resolved_ip_lit = repr(pre_resolved_ip) if pre_resolved_ip else "None"
    check_code = f"""
import json
from blockchecks.checkers.http3 import check_http3, http3_result_dict
r = check_http3({domain!r}, {timeout}, pre_resolved_ip={resolved_ip_lit})
print(json.dumps(http3_result_dict(r)))
"""
    try:
        proc = sp.run(
            ["sudo", "ip", "netns", "exec", ns_name, python_bin, "-c", check_code],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {
                **_QUIC_FAIL,
                "error": f"parse: {(proc.stdout or '')[:100]}",
            }
    except sp.TimeoutExpired:
        return {**_QUIC_FAIL, "error": "timeout"}
    except (OSError, ValueError) as exc:
        return {**_QUIC_FAIL, "error": str(exc)[:120]}
