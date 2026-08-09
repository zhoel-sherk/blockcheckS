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
from curl_cffi.requests import RequestsError

from blockchecks.checkers.dns_secure import CURLOPT_RESOLVE
from blockchecks.checkers.tcp_tls import DPI_FAKE_PATTERNS, classify_http_status
from blockchecks.engine.config import (
    CURLOPT_ECH,
    GGC_RANGE_SIZE,
    GOOGLEVIDEO_RANGE_SIZE,
    MIN_READ_RATE_BPS,
    SOCKS5_PROXY,
    THROTTLED_MAX_BPS,
)

try:
    CURLOPT_IPRESOLVE = curl_cffi.CurlOpt.IPRESOLVE
except AttributeError:
    CURLOPT_IPRESOLVE = 113
_CURL_IPRESOLVE_V4 = 1

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
    ggc: bool = False
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
    *,
    timeout: float = 5.0,
) -> tuple[CurlProbeRequest, dict | None]:
    """Build probe request for videoplayback URL or return error dict.

    When ``BLOCKCHECKS_GV_GGC=1`` uses the deterministic GGC probe instead
    (no yt-dlp signature, valid beyond the 6-hour signed-URL TTL).
    """
    from blockchecks.checkers.dns_secure import doh_query, pick_working_doh
    from blockchecks.checkers.youtube_url import get_fresh_url, videoplayback_host
    from blockchecks.engine.config import GGC_ENABLED

    if GGC_ENABLED:
        return prepare_ggc_probe(domain, timeout=timeout, resolved_ip=resolved_ip)

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
            timeout=timeout,
            resolved_ip=resolved_ip,
            resolve_name=resolve_name,
            curl_url=curl_url,
            disable_ech=True,
            googlevideo=True,
        ),
        None,
    )


def prepare_ggc_probe(
    domain: str,
    *,
    timeout: float = 5.0,
    resolve_name: str | None = None,
    resolved_ip: str | None = None,
) -> tuple[CurlProbeRequest, dict | None]:
    """Deterministic GGC probe — no yt-dlp signature required.

    Hits a live Google cache (GGC) IP with SNI = ``rr*.googlevideo.com`` and a
    large Range header (1MiB) to trigger the TSPU "video download" heuristic.
    The signed googlevideo URLs expire in 6h, but the GGC-IP + SNI + Range
    pattern is valid indefinitely and yields different answers on bypass
    (CDN responds with any HTTP status) vs block (timeout / RST).
    """
    from blockchecks.checkers.dns_secure import doh_query, pick_working_doh
    from blockchecks.engine.config import GGC_FALLBACK_IP, GGC_HOST

    host = resolve_name or GGC_HOST
    ip = resolved_ip
    if not ip:
        try:
            ips, err, _ = doh_query(host, pick_working_doh(), timeout=5.0)
            if ips and not err:
                ip = ips[0]
        except Exception:
            ip = None
    if not ip:
        ip = GGC_FALLBACK_IP

    return (
        CurlProbeRequest(
            domain=domain,
            timeout=timeout,
            resolved_ip=ip,
            resolve_name=host,
            curl_url=f"https://{host}/videoplayback?ip={ip}",
            disable_ech=True,
            googlevideo=True,
            ggc=True,
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
    ggc: bool = False,
) -> tuple[CurlProbeRequest, dict | None]:
    """Resolve googlevideo-specific fields when needed."""
    if protocol != "http" and is_googlevideo_domain(domain):
        if ggc:
            return prepare_ggc_probe(domain, timeout=timeout, resolved_ip=resolved_ip)
        return prepare_googlevideo_probe(domain, resolved_ip=resolved_ip, timeout=timeout)
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


def _ggc_redirect_is_google(location: str) -> bool:
    """True if a 302/307 Location stays inside Google-owned domains.

    The TSPU stub redirects to regional Russian IPs / foreign domains; a
    genuine Google load-balancer redirect keeps the host inside
    ``*.googlevideo.com`` / ``*.google.com``.
    """
    from urllib.parse import urlparse

    if not location:
        return False
    host = (urlparse(location).hostname or "").lower()
    if not host:
        return False
    return (
        host == "googlevideo.com"
        or host.endswith(".googlevideo.com")
        or host == "google.com"
        or host.endswith(".google.com")
    )


def _googlevideo_follow_request(req: CurlProbeRequest, location: str) -> CurlProbeRequest | None:
    """Build a one-hop follow-up request for CDN redirects between googlevideo hosts."""
    from urllib.parse import urlparse

    if not location or "googlevideo.com" not in location.lower():
        return None
    target = location if location.startswith("http") else f"https://{location}"
    host = (urlparse(target).hostname or "").lower()
    if "googlevideo" not in host:
        return None
    return CurlProbeRequest(        domain=req.domain,
        timeout=req.timeout,
        resolved_ip=None,
        resolve_name=host,
        curl_url=target,
        disable_ech=req.disable_ech,
        googlevideo=True,
        protocol=req.protocol,
    )


def run_curl_probe(req: CurlProbeRequest, *, _gv_hop: int = 0) -> CurlProbeResult:
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
        headers["Range"] = (
            f"bytes=0-{GGC_RANGE_SIZE - 1}" if req.ggc else googlevideo_range_header()
        )
        headers["Referer"] = "https://www.youtube.com/"
        headers["Origin"] = "https://www.youtube.com"

    start = time.perf_counter()
    try:
        with curl_cffi.Session(
            impersonate="chrome124",
            http_version=2,
            headers=headers,
            allow_redirects=False,
        ) as session:
            if req.googlevideo:
                session.curl.setopt(CURLOPT_IPRESOLVE, _CURL_IPRESOLVE_V4)
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
            curl_timeout = min(req.timeout, 8.0) if req.googlevideo else req.timeout
            # googlevideo CDN is often only reachable via the SOCKS proxy
            # (direct egress blocked by DPI on Fryazino). Pass it per-request via
            # the proxy= kw (socks5h = DNS through proxy); CurlOpt.PROXY setopt
            # does not map socks5h correctly and yields 403.
            get_kwargs: dict = {}
            if req.googlevideo and SOCKS5_PROXY:
                get_kwargs["proxy"] = SOCKS5_PROXY.replace("socks5://", "socks5h://")
            resp = session.get(url, timeout=curl_timeout, **get_kwargs)
    except RequestsError as e:
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
    server_hdr = resp.headers.get("Server") or resp.headers.get("server") or ""

    # GGC probe (deterministic, no signature): a genuine Google CDN answer is
    # recognized by the unique Server header (gws / scone / gvs) and, on 302/307,
    # by a Location that stays inside *.googlevideo.com / *.google.com. The TSPU
    # stub replies with Server: nginx/nts (or none) and redirects to regional
    # Russian IPs/domains. timeout/RST (handled in except) == blocked.
    if req.ggc:
        server = server_hdr.lower()
        google_server = any(t in server for t in ("gws", "scone", "gvs"))
        status = resp.status_code
        if status in {301, 302, 303, 307, 308} and not _ggc_redirect_is_google(loc):
            return CurlProbeResult(
                success=False,
                http_code=status,
                latency_ms=elapsed * 1000,
                content_len=clen,
                read_rate_bps=rate,
                error=f"tspu redirect to {loc[:80]}",
            )
        if not google_server:
            return CurlProbeResult(
                success=False,
                http_code=status,
                latency_ms=elapsed * 1000,
                content_len=clen,
                read_rate_bps=rate,
                error=f"non-google server header: {server_hdr[:40]!r}",
            )
        return CurlProbeResult(
            success=True,
            http_code=status,
            latency_ms=elapsed * 1000,
            content_len=clen,
            content_ok=clen >= 300,
            throttled=rate < THROTTLED_MAX_BPS and clen >= 300,
            read_rate_bps=rate,
            error=None,
        )

    redirect_domain = "googlevideo.com" if req.googlevideo else dom
    redirect_err = classify_http_status(redirect_domain, resp.status_code, loc)
    if (
        req.googlevideo
        and _gv_hop == 0
        and resp.status_code in {301, 302, 303, 307, 308}
        and not redirect_err
    ):
        follow = _googlevideo_follow_request(req, loc)
        if follow:
            return run_curl_probe(follow, _gv_hop=1)
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
    dpi_fake = any(p in body.lower() for p in DPI_FAKE_PATTERNS)
    if dpi_fake:
        content_ok = False

    # Tiny 206 is OK for ordinary sites; googlevideo Range must meet size budget
    small_206 = resp.status_code == 206 and clen < 300 and not req.googlevideo
    small_body_ok = (not dpi_fake) and (resp.status_code in _SMALL_BODY_STATUSES or small_206)
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


MAX_CURL_REPEATS = 10  # GP DiscoveryOptions cap


def clamp_repeats(n: int) -> int:
    """Bound curl repeats to GP/blockcheck2 practical range (1..10)."""
    return max(1, min(MAX_CURL_REPEATS, int(n)))


def worker_wall_timeout(
    probe_timeout: float,
    repeats: int = 1,
    *,
    n_domains: int = 1,
    curl_parallel: int = 1,
    parallel_repeats: bool = False,
    settle_slack: float = 3.0,
) -> float:
    """Subprocess wall-clock budget for curl probe worker (repeats-aware).

    sequential repeats need ~repeats × timeout per domain wave;
    parallel_repeats collapses repeats into one wave (~1× timeout).
    """
    import math

    r = max(1, int(repeats))
    n = max(1, int(n_domains))
    par = max(1, int(curl_parallel))
    waves = math.ceil(n / par)
    per_wave = float(probe_timeout) if parallel_repeats and r > 1 else float(probe_timeout) * r
    return per_wave * waves + max(3.0, float(settle_slack))


def run_curl_probe_with_repeats(
    req: CurlProbeRequest,
    *,
    repeats: int = 1,
    parallel_repeats: bool = False,
    repeats_mode: str = "fast",
    quick_break: bool = False,
) -> dict:
    """Run probe with blockcheck2-style repeats.

    *fast* (default): stop on first PASS (blockcheckS mass-scan speed).
    *stable*: run all N attempts; PASS if any succeeded (BC2 stability test).
    *quick_break*: on sequential FAIL, stop early (BC2 SCANLEVEL=quick).
    """
    n = clamp_repeats(repeats)
    stable = repeats_mode == "stable"

    if parallel_repeats and n > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            futs = [ex.submit(run_curl_probe, req) for _ in range(n)]
            first_pass: CurlProbeResult | None = None
            last: CurlProbeResult | None = None
            for fut in concurrent.futures.as_completed(futs):
                result = fut.result()
                last = result
                if result.success:
                    if first_pass is None:
                        first_pass = result
                    if not stable:
                        return result.as_dict()
            if first_pass is not None:
                return first_pass.as_dict()
            if last is not None:
                return last.as_dict()
        return CurlProbeResult(error="all parallel repeats failed").as_dict()

    first_pass: CurlProbeResult | None = None
    last: CurlProbeResult | None = None
    for _ in range(n):
        last = run_curl_probe(req)
        if last.success:
            if first_pass is None:
                first_pass = last
            if not stable:
                return last.as_dict()
        elif quick_break:
            break
    if first_pass is not None:
        return first_pass.as_dict()
    return (last or CurlProbeResult()).as_dict()


@dataclass
class CurlProbeBatch:
    requests: list[CurlProbeRequest] = field(default_factory=list)
    curl_parallel: int = 4
    repeats: int = 1
    parallel_repeats: bool = False
    repeats_mode: str = "fast"
    quick_break: bool = False


def run_curl_probe_batch(batch: CurlProbeBatch) -> dict[str, dict]:
    """Parallel curl across domains (one nfqws2 session assumed by caller)."""
    if not batch.requests:
        return {}

    workers = max(1, min(int(batch.curl_parallel), len(batch.requests)))
    repeats = clamp_repeats(batch.repeats)

    def run_one(req: CurlProbeRequest) -> dict:
        return run_curl_probe_with_repeats(
            req,
            repeats=repeats,
            parallel_repeats=batch.parallel_repeats,
            repeats_mode=batch.repeats_mode,
            quick_break=batch.quick_break,
        )

    out: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(run_one, req): req.domain for req in batch.requests}
        for fut in concurrent.futures.as_completed(futs):
            domain = futs[fut]
            out[domain] = fut.result()
    return out


def repeats_from_args(args) -> tuple[int, bool, str, bool]:
    """Parse repeats CLI into (repeats, parallel_repeats, repeats_mode, quick_break)."""
    repeats = clamp_repeats(getattr(args, "repeats", 1) or 1)
    parallel = bool(getattr(args, "parallel_repeats", False))
    mode = getattr(args, "repeats_mode", "fast") or "fast"
    scan_level = getattr(args, "scan_level", "fast") or "fast"
    quick_break = scan_level in ("single", "fast") and mode == "stable"
    return repeats, parallel, mode, quick_break
