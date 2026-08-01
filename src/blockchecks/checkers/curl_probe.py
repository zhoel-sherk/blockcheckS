"""TCP/HTTP curl_cffi probe for strategy tests (GV-3).

Centralizes curl session setup: ECH disable via ``Session.curl.setopt`` only —
never ``options=`` on ``curl_cffi.get()`` / ``Session.request()`` (broken in
curl_cffi >= 0.15). Used by async_runner, test_runner, and hostfakesplit /
googlevideo videoplayback checks.
"""

from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field

import curl_cffi

from blockchecks.checkers.dns_secure import CURLOPT_RESOLVE
from blockchecks.checkers.tcp_tls import classify_http_status
from blockchecks.engine.config import (
    CURLOPT_ECH,
    GOOGLEVIDEO_RANGE_SIZE,
    MIN_READ_RATE_BPS,
    THROTTLED_MAX_BPS,
)

_DPI_FAKE_PATTERNS = (
    b"roskomnadzor",
    b"rkn.gov.ru",
    b"blockpage",
    b"utmblock",
)

_SMALL_BODY_STATUSES = frozenset({101, 204, 301, 302, 303, 304, 307, 308})


@dataclass
class CurlProbeRequest:
    domain: str
    timeout: float = 5.0
    resolved_ip: str | None = None
    resolve_name: str | None = None
    curl_url: str | None = None
    disable_ech: bool = False
    googlevideo: bool = False
    protocol: str = "tls12"


@dataclass
class CurlProbeResult:
    success: bool = False
    http_code: int = 0
    latency_ms: float = 0.0
    content_len: int = 0
    content_ok: bool = False
    throttled: bool = False
    read_rate_bps: float = 0.0
    error: str | None = None

    def as_dict(self) -> dict:
        return {
            "success": self.success,
            "http_code": self.http_code,
            "latency_ms": self.latency_ms,
            "content_len": self.content_len,
            "content_ok": self.content_ok,
            "throttled": self.throttled,
            "read_rate_bps": self.read_rate_bps,
            "error": self.error,
        }


def is_googlevideo_domain(domain: str) -> bool:
    return "googlevideo" in domain.lower()


def googlevideo_range_header() -> str:
    return f"bytes=0-{GOOGLEVIDEO_RANGE_SIZE - 1}"


def prepare_googlevideo_probe(
    domain: str,
    resolved_ip: str | None = None,
) -> tuple[CurlProbeRequest, dict | None]:
    """Build probe request for videoplayback URL or return error dict."""
    from blockchecks.checkers.dns_secure import doh_query, pick_working_doh
    from blockchecks.checkers.youtube_url import get_fresh_url, videoplayback_host

    curl_url = get_fresh_url()
    if not curl_url:
        return CurlProbeRequest(domain=domain), {
            "success": False,
            "http_code": 0,
            "latency_ms": 0,
            "content_len": 0,
            "content_ok": False,
            "throttled": False,
            "read_rate_bps": 0,
            "error": "gv_url_unavailable",
        }

    resolve_name = videoplayback_host(curl_url) or domain.split("/")[0]
    dom = domain.lower().split("/")[0]
    if resolve_name and resolve_name != dom:
        ips, err, _ = doh_query(resolve_name, pick_working_doh(), timeout=5.0)
        if ips and not err:
            resolved_ip = ips[0]

    return (
        CurlProbeRequest(
            domain=domain,
            resolved_ip=resolved_ip,
            resolve_name=resolve_name,
            curl_url=curl_url,
            disable_ech=True,
            googlevideo=True,
        ),
        None,
    )


def build_probe_request(
    domain: str,
    *,
    timeout: float = 5.0,
    resolved_ip: str | None = None,
    disable_ech: bool = False,
    protocol: str = "tls12",
) -> tuple[CurlProbeRequest, dict | None]:
    """Resolve googlevideo-specific fields when needed."""
    if protocol != "http" and is_googlevideo_domain(domain):
        return prepare_googlevideo_probe(domain, resolved_ip=resolved_ip)
    use_ech_off = disable_ech
    return (
        CurlProbeRequest(
            domain=domain,
            timeout=timeout,
            resolved_ip=resolved_ip,
            resolve_name=domain.split("/")[0],
            disable_ech=use_ech_off,
            protocol=protocol,
        ),
        None,
    )


def _apply_ech_off(session: curl_cffi.Session) -> str | None:
    """Disable ECH via low-level setopt; return error string on total failure."""
    try:
        session.curl.setopt(curl_cffi.CurlOpt.ECH, "")
        return None
    except Exception:
        pass
    try:
        session.curl.setopt(CURLOPT_ECH, "")
        return None
    except Exception as e:
        return f"ech_setopt:{e!s}"[:100]


def run_curl_probe(req: CurlProbeRequest) -> CurlProbeResult:
    """Execute one curl probe (hostfakesplit / generic TLS / googlevideo chunk)."""
    import time

    is_http = req.protocol == "http"
    url_scheme = "http" if is_http else "https"
    resolve_port = 80 if is_http else 443
    resolve_name = (req.resolve_name or req.domain).split("/")[0]
    dom = resolve_name.lower().split("/")[0]
    use_ech_off = req.disable_ech or req.googlevideo

    headers: dict[str, str] = {"Accept": "text/html"}
    if req.googlevideo:
        headers["Range"] = googlevideo_range_header()

    start = time.perf_counter()
    try:
        session = curl_cffi.Session(
            impersonate="chrome124",
            http_version=2,
            headers=headers,
            allow_redirects=False,
        )
        if req.resolved_ip:
            session.curl.setopt(
                CURLOPT_RESOLVE,
                [f"{resolve_name}:{resolve_port}:{req.resolved_ip}"],
            )
        if use_ech_off:
            ech_err = _apply_ech_off(session)
            if ech_err:
                return CurlProbeResult(
                    latency_ms=(time.perf_counter() - start) * 1000,
                    error=ech_err,
                )
        url = req.curl_url if req.curl_url else f"{url_scheme}://{req.domain}"
        resp = session.get(url, timeout=min(req.timeout, 1.5))
    except curl_cffi.CurlError as e:
        msg = str(e)
        return CurlProbeResult(
            latency_ms=(time.perf_counter() - start) * 1000,
            error="timeout" if "Timeout" in msg else msg[:120],
        )
    except Exception as e:
        return CurlProbeResult(error=str(e)[:120])

    elapsed = max(time.perf_counter() - start, 0.001)
    body = resp.content[:4096]
    clen = len(resp.content)
    rate = clen / elapsed
    loc = resp.headers.get("Location") or resp.headers.get("location") or ""

    redirect_err = classify_http_status(dom, resp.status_code, loc)
    if redirect_err:
        return CurlProbeResult(
            success=False,
            http_code=resp.status_code,
            latency_ms=elapsed * 1000,
            content_len=clen,
            read_rate_bps=rate,
            error=redirect_err,
        )
    if resp.status_code == 400:
        return CurlProbeResult(
            success=False,
            http_code=400,
            latency_ms=elapsed * 1000,
            content_len=clen,
            read_rate_bps=rate,
            error="http 400 (likely fake packets received)",
        )

    content_ok = clen >= 300
    dpi_fake = any(p in body.lower() for p in _DPI_FAKE_PATTERNS)
    if dpi_fake:
        content_ok = False

    small_body_ok = (not dpi_fake) and (
        resp.status_code in _SMALL_BODY_STATUSES
        or (resp.status_code == 206 and clen < 300)
    )
    status_ok = 200 <= resp.status_code < 400
    throttled = False
    success = False
    if status_ok and (content_ok or small_body_ok) and not dpi_fake:
        if rate < MIN_READ_RATE_BPS and not small_body_ok:
            success = False
        elif rate < THROTTLED_MAX_BPS and not small_body_ok and clen >= 300:
            success = True
            throttled = True
        else:
            success = True

    return CurlProbeResult(
        success=success,
        http_code=resp.status_code,
        latency_ms=elapsed * 1000,
        content_len=clen,
        content_ok=content_ok,
        throttled=throttled,
        read_rate_bps=rate,
        error=None,
    )


def run_curl_probe_with_repeats(
    req: CurlProbeRequest,
    *,
    repeats: int = 1,
    parallel_repeats: bool = False,
) -> dict:
    """Run probe with blockcheck2-style repeats; stop early on first PASS."""
    n = max(1, int(repeats))
    if parallel_repeats and n > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            futs = [ex.submit(run_curl_probe, req) for _ in range(n)]
            last: CurlProbeResult | None = None
            for fut in concurrent.futures.as_completed(futs):
                last = fut.result()
                if last.success:
                    return last.as_dict()
            if last is not None:
                return last.as_dict()
        return CurlProbeResult(error="all parallel repeats failed").as_dict()

    last: CurlProbeResult | None = None
    for _ in range(n):
        last = run_curl_probe(req)
        if last.success:
            return last.as_dict()
    return (last or CurlProbeResult()).as_dict()


@dataclass
class CurlProbeBatch:
    requests: list[CurlProbeRequest] = field(default_factory=list)
    curl_parallel: int = 4
    repeats: int = 1


def run_curl_probe_batch(batch: CurlProbeBatch) -> dict[str, dict]:
    """Parallel curl across domains (one nfqws2 session assumed by caller)."""
    if not batch.requests:
        return {}

    workers = max(1, min(int(batch.curl_parallel), len(batch.requests)))
    repeats = max(1, int(batch.repeats))

    def run_one(req: CurlProbeRequest) -> dict:
        return run_curl_probe_with_repeats(req, repeats=repeats, parallel_repeats=False)

    out: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(run_one, req): req.domain for req in batch.requests}
        for fut in concurrent.futures.as_completed(futs):
            domain = futs[fut]
            out[domain] = fut.result()
    return out
