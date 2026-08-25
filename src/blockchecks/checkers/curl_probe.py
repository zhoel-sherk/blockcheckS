"""HTTPS/HTTP probes via curl_cffi.
Session setup (ECH, impersonate, proxy, Range) is shared by all runners.
Do not pass options= to get()/request() on curl_cffi >= 0.15; use Session.curl.setopt.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import re
from dataclasses import dataclass, field

import curl_cffi
from curl_cffi.requests import RequestsError

from blockchecks.checkers.dns_secure import CURLOPT_RESOLVE
from blockchecks.checkers.tcp_tls import DPI_FAKE_PATTERNS, classify_http_status
from blockchecks.engine.config import (
    CURLOPT_ECH,
    DOH_TIMEOUT,
    GGC_RANGE_SIZE,
    GOOGLEVIDEO_RANGE_SIZE,
    MIN_READ_RATE_BPS,
    SOCKS5_PROXY,
    THROTTLED_MAX_BPS,
    WALL_SLACK,
)

#: TLS/HTTP fingerprint target for all probes. Pinned to chrome124 by default
#: so campaign results stay comparable across runs; override per-run with
#: BLOCKCHECKS_IMPERSONATE (e.g. "chrome" -> latest preset, currently chrome150).
DEFAULT_IMPERSONATE = "chrome124"


def impersonate_target() -> str:
    """Resolved curl_cffi impersonate target (env override, validated lazily)."""
    val = (os.environ.get("BLOCKCHECKS_IMPERSONATE") or "").strip()
    return val or DEFAULT_IMPERSONATE


try:
    CURLOPT_IPRESOLVE = curl_cffi.CurlOpt.IPRESOLVE
except AttributeError:
    CURLOPT_IPRESOLVE = 113
_CURL_IPRESOLVE_V4 = 1

log = logging.getLogger(__name__)

_SMALL_BODY_STATUSES = frozenset({101, 204, 206, 301, 302, 303, 307, 308})
_TLS_BYPASS_PROOF_STATUSES = frozenset({401, 403, 404})

#: Path-segment tokens of a same-host redirect that is still a provider stub.
#: Matched as whole path segments (not substrings) so ``/login?error=...`` is OK.
_BLOCK_PATH_TOKENS = frozenset({"block", "blocked", "blockpage", "forbidden", "stop", "error"})
_HANDSHAKE_BUDGET_SEC = 2.0  # TLS/TCP setup; small bodies cannot yield a transfer rate
_THROTTLE_MIN_BODY = 16 * 1024  # below this, whole-connection rate is handshake-dominated


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
    ytcdn: bool = False
    ytcdn_proxy: bool = False
    ytcdn_bare: bool = False
    protocol: str = "tls12"


@dataclass
class CurlProbeResult:
    resolve_name: str = ""  # SNI, которым реально зондиовали (ggc-пул)
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
            "resolve_name": self.resolve_name,
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


#: YouTube family hosts (site + static CDN). SNI-blocked on some ISPs; probed
#: with a deterministic Google-answer detector (like GGC) — no yt-dlp signature.
_YOUTUBE_RE = re.compile(
    r"(?:^|\.)"
    r"(youtube\.com|youtu\.be|googlevideo\.com|ytimg\.com|ggpht\.com|"
    r"gvt1\.com|youtubeusercontent\.com|googleusercontent\.com)"
    r"(?:\.|$)"
)


def is_youtube_domain(domain: str) -> bool:
    """True for any YouTube-family host (site, googlevideo, static CDN)."""
    d = domain.lower().split("/")[0]
    return bool(_YOUTUBE_RE.search(d))


def is_ytcdn_domain(domain: str) -> bool:
    """True for YouTube static CDN hosts (not youtube.com / googlevideo itself)."""
    d = domain.lower().split("/")[0]
    if not is_youtube_domain(d):
        return False
    return "googlevideo" not in d and "youtube.com" not in d and d != "youtu.be"


#: Server-header fragments identifying a genuine Google frontend. The TSPU
#: stub replies with ``nginx/nts`` (or none); Google uses gws (web), scone/gvs
#: (googlevideo cache), sffe (static content / ytimg), bandaid (misdirected
#: traffic server on some googlevideo/static endpoints), etc.
_GOOGLE_SERVER_HINTS = ("gws", "scone", "gvs", "sffe", "fife", "bandaid")


def googlevideo_range_header() -> str:
    return f"bytes=0-{GOOGLEVIDEO_RANGE_SIZE - 1}"


def prepare_googlevideo_probe(
    domain: str,
    resolved_ip: str | None = None,
    *,
    timeout: float = 5.0,
) -> tuple[CurlProbeRequest, dict | None]:
    """Build probe request for videoplayback URL or return error dict.

    googlevideo hosts are always probed via the deterministic GGC detector
    (no yt-dlp signature, valid beyond the 6-hour signed-URL TTL). Disable with
    ``BLOCKCHECKS_GV_GGC=0`` to fall back to the signed yt-dlp URL.
    """
    from blockchecks.checkers.dns_secure import doh_query, pick_working_doh
    from blockchecks.checkers.youtube_url import get_fresh_url, videoplayback_host
    from blockchecks.engine.config import ggc_enabled

    if ggc_enabled(domain):
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
        ips, err, _ = doh_query(resolve_name, pick_working_doh(), timeout=DOH_TIMEOUT)
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


def prepare_ytcdn_probe(
    domain: str,
    *,
    timeout: float = 5.0,
    resolved_ip: str | None = None,
) -> tuple[CurlProbeRequest, dict | None]:
    """Deterministic probe for YouTube static CDN hosts (ytimg/ggpht/gvt1/...).

    Like the GGC detector, a genuine Google CDN answer — any HTTP status from
    a Google ``gws``/``scone``/``gvs`` server — proves the bypass works without
    needing a signed URL. The probe tries up to three variants:

      1. bare host: ``https://{host}/`` — any real CDN answer counts (404/403
         still proves TLS reached Google, not the TSPU stub)
      2. via SOCKS: the same URL through ``SOCKS5_PROXY`` (dead-socks safe:
         empty BLOCKCHECKS_PROXY disables the fallback, like googlevideo)
      3. host with a stable thumbnail path (i.ytimg/ggpht deterministic 200)

    The first variant that returns a genuine Google answer wins. A DPI
    timeout/RST (handled by the caller) == blocked.
    """
    variants = ytcdn_probe_variants(domain, timeout=timeout, resolved_ip=resolved_ip)
    return variants[0], None


def ytcdn_probe_variants(
    domain: str,
    *,
    timeout: float = 5.0,
    resolved_ip: str | None = None,
) -> list[CurlProbeRequest]:
    """Build up-to-three deterministic yt-cdn probe variants (see prepare_ytcdn_probe)."""
    from blockchecks.engine.config import SOCKS5_PROXY

    d = domain.lower().split("/")[0]

    # Stable 200 path per CDN family (no signature; valid indefinitely).
    thumb_path = ""
    if d.endswith(".ytimg.com"):
        thumb_path = "/vi/dQw4w9WgXcQ/0.jpg"
    elif d.endswith(".ggpht.com"):
        thumb_path = "/ytc/AAUvw7g0mI5qo0r5vz0uR3sM0Q6P0F0w1Q4mXlLxM.png"

    variants: list[CurlProbeRequest] = []
    bare = f"https://{d}/"
    # Priority: stable thumbnail (deterministic 200) → SOCKS → bare host.
    if thumb_path:
        variants.append(
            CurlProbeRequest(
                domain=domain,
                timeout=timeout,
                resolved_ip=resolved_ip,
                resolve_name=d,
                curl_url=f"https://{d}{thumb_path}",
                disable_ech=True,
                ytcdn=True,
                protocol="tls12",
            )
        )
    if SOCKS5_PROXY:
        variants.append(
            CurlProbeRequest(
                domain=domain,
                timeout=timeout,
                resolved_ip=resolved_ip,
                resolve_name=d,
                curl_url=bare if not thumb_path else f"https://{d}{thumb_path}",
                disable_ech=True,
                ytcdn=True,
                ytcdn_proxy=True,
                protocol="tls12",
            )
        )
    variants.append(
        CurlProbeRequest(
            domain=domain,
            timeout=timeout,
            resolved_ip=resolved_ip,
            resolve_name=d,
            curl_url=bare,
            disable_ech=True,
            ytcdn=True,
            ytcdn_bare=True,
            protocol="tls12",
        )
    )
    return variants


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

    SNI управляется подборщиком: режимы synthetic/real/fixed и цепочка
    резолва — в ``engine/ggc_pool``. ``resolve_name`` извне принудительно
    фиксирует хост (legacy A/B).
    """
    from blockchecks.checkers.dns_secure import doh_query, pick_working_doh
    from blockchecks.engine.config import GGC_FALLBACK_IP
    from blockchecks.engine.ggc_pool import (
        pick_target,
        remember_ggc_ip,
        resolve_ip_chain,
    )

    target = pick_target(domain)
    host = resolve_name or target.host
    ip = resolved_ip or target.ip_hint
    if not ip:
        try:
            ips, err, _ = doh_query(host, pick_working_doh(), timeout=DOH_TIMEOUT)
            if ips and not err:
                ip = ips[0]
                remember_ggc_ip(host, ip)
        except Exception as exc:
            log.warning("GGC DoH for %s failed: %s", host, exc)
            ip = None
    if not ip:
        # Цепочка: dns.db → [google].fallback_ips/env → CACHE/ggc_ips.json
        ip = resolve_ip_chain(host)
    if not ip:
        # Последний рубеж — известный живой GGC-IP: edge отвечает wildcard-серт.
        # *.googlevideo.com на любой SNI этого домена.
        log.warning("%s", f"  WARNING: no IP for {host}; using legacy fallback {GGC_FALLBACK_IP}")
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


_ech_warned = False


def _apply_ech_off(session: curl_cffi.Session) -> str | None:
    """Disable ECH via low-level setopt; best-effort, никогда не фейлит пробу.

    Вшитый libcurl может не знать CURLOPT_ECH (10325 появился в curl 8.8):
    тогда клиент в принципе не предлагает ECH — цель «выключить ECH» уже
    достигнута дефолтом. Ошибка setopt НЕ должна абортировать пробу
    (25.08: убила 100% googlevideo/static попыток).
    """
    global _ech_warned
    try:
        session.curl.setopt(curl_cffi.CurlOpt.ECH, "")
        return None
    except Exception:
        pass
    try:
        session.curl.setopt(CURLOPT_ECH, "")
        return None
    except Exception as e:
        if not _ech_warned:
            _ech_warned = True
            log.warning(
                "ECH disable unsupported by bundled libcurl (%s) — "
                "continuing without ECH-off (client never offers ECH anyway)",
                str(e)[:80],
            )
        return None


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
    return CurlProbeRequest(
        domain=req.domain,
        timeout=req.timeout,
        resolved_ip=req.resolved_ip,
        resolve_name=host,
        curl_url=target,
        disable_ech=req.disable_ech,
        googlevideo=True,
        protocol=req.protocol,
    )


def _location_is_blockpage(location: str) -> bool:
    """True if Location path has a block/error *segment* (not a query substring)."""
    from urllib.parse import urlparse

    raw = (location or "").strip()
    if not raw:
        return False
    if "://" not in raw and not raw.startswith("//"):
        raw = "https://x" + (raw if raw.startswith("/") else f"/{raw}")
    path = (urlparse(raw).path or "").lower()
    return "blockpage" in path or any(seg in _BLOCK_PATH_TOKENS for seg in path.split("/") if seg)


def _block_redirect_err(status: int, location: str) -> str | None:
    """Same-host redirect to an obvious block/error path — provider stub.

    ``is_suspicious_redirect`` only flags foreign-host Location values, so a
    stub answering ``302 Location: https://<same-host>/block`` would otherwise
    be classified as a working bypass. Query strings like ``/login?error=``
    are not blockpages.
    """
    if status not in {301, 302, 303, 307, 308}:
        return None
    if _location_is_blockpage(location):
        return f"blockpage redirect {status} to {location[:80]}"
    return None


def _classify_throughput(
    clen: int, elapsed: float, *, small_body_ok: bool
) -> tuple[bool, bool, float]:
    """Return (rate_ok, throttled, rate) from body size and wall-clock elapsed.

    Whole-connection elapsed includes TLS handshake. Dividing a small body by
    that time falsely yields THROTTLED/FAIL; skip rate verdicts unless the
    wait is a clear stall or the body is large enough that transfer dominates.
    """
    rate = clen / max(elapsed, 0.001)
    if small_body_ok:
        return True, False, rate
    if rate < MIN_READ_RATE_BPS and elapsed >= _HANDSHAKE_BUDGET_SEC:
        return False, False, rate
    if clen < _THROTTLE_MIN_BODY:
        return True, False, rate
    if rate < MIN_READ_RATE_BPS:
        return False, False, rate
    return True, rate < THROTTLED_MAX_BPS, rate


def _stub_body_err(req: CurlProbeRequest, resp, clen: int) -> str | None:
    """Reject stub answers on paths that must carry binary payloads.

    - 304 Not Modified without a prior conditional request is anomalous for a
      plain GET → provider stub / uncached answer.
    - googlevideo/ytcdn binary-API probes must never receive text/html.
    """
    if resp.status_code == 304 and not req.googlevideo:
        return "http 304 without conditional request (likely stub)"
    if (req.googlevideo or req.ytcdn or req.ggc) and resp.status_code == 200:
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "html" in ctype or (not ctype and clen < 300):
            return "text/html or empty content on binary-API probe"
    return None


def _resp_fail(resp, elapsed: float, clen: int, rate: float, error: str) -> CurlProbeResult:
    return CurlProbeResult(
        success=False,
        http_code=resp.status_code,
        latency_ms=elapsed * 1000,
        content_len=clen,
        read_rate_bps=rate,
        error=error,
    )


def _curl_proxy_kwargs(req: CurlProbeRequest) -> dict:
    if (req.googlevideo or req.ytcdn_proxy) and SOCKS5_PROXY:
        return {"proxy": SOCKS5_PROXY.replace("socks5://", "socks5h://")}
    return {}


def _open_curl_session(req: CurlProbeRequest) -> curl_cffi.Session | CurlProbeResult:
    """Build a configured Session, or a CurlProbeResult on ECH/setopt failure."""
    is_http = req.protocol == "http"
    resolve_port = 80 if is_http else 443
    resolve_name = (req.resolve_name or req.domain).split("/")[0]
    headers: dict[str, str] = {"Accept": "text/html"}
    if req.googlevideo:
        headers["Range"] = (
            f"bytes=0-{GGC_RANGE_SIZE - 1}" if req.ggc else googlevideo_range_header()
        )
        headers["Referer"] = "https://www.youtube.com/"
        headers["Origin"] = "https://www.youtube.com"
    session = curl_cffi.Session(
        impersonate=impersonate_target(),
        http_version="v1" if is_http else 2,
        headers=headers,
        allow_redirects=False,
    )
    if req.googlevideo:
        session.curl.setopt(CURLOPT_IPRESOLVE, _CURL_IPRESOLVE_V4)
    if req.resolved_ip:
        session.curl.setopt(
            CURLOPT_RESOLVE,
            [f"{resolve_name}:{resolve_port}:{req.resolved_ip}"],
        )
    if not (req.disable_ech or req.googlevideo):
        return session
    if ech_err := _apply_ech_off(session):
        session.close()
        return CurlProbeResult(error=ech_err)
    return session


def _classify_google_cdn(
    req: CurlProbeRequest,
    resp,
    clen: int,
    elapsed: float,
    loc: str,
    server_hdr: str,
) -> CurlProbeResult | None:
    if not (req.ggc or req.ytcdn):
        return None
    rate = clen / elapsed
    google_server = any(t in server_hdr.lower() for t in _GOOGLE_SERVER_HINTS)
    if (
        req.ggc
        and resp.status_code in {301, 302, 303, 307, 308}
        and not _ggc_redirect_is_google(loc)
    ):
        return _resp_fail(resp, elapsed, clen, rate, f"tspu redirect to {loc[:80]}")
    if not google_server:
        return _resp_fail(
            resp, elapsed, clen, rate, f"non-google server header: {server_hdr[:40]!r}"
        )
    _, throttled, rate = _classify_throughput(clen, elapsed, small_body_ok=clen < 300)
    return CurlProbeResult(
        success=True,
        http_code=resp.status_code,
        latency_ms=elapsed * 1000,
        content_len=clen,
        content_ok=clen >= 300,
        throttled=throttled,
        read_rate_bps=rate,
        error=None,
    )


def _classify_generic(
    req: CurlProbeRequest,
    resp,
    elapsed: float,
    clen: int,
    loc: str,
    redirect_err: str | None,
) -> CurlProbeResult:
    rate = clen / elapsed
    if redirect_err:
        return _resp_fail(resp, elapsed, clen, rate, redirect_err)
    if block_err := _block_redirect_err(resp.status_code, loc):
        return _resp_fail(resp, elapsed, clen, rate, block_err)
    if resp.status_code == 400:
        return _resp_fail(resp, elapsed, clen, rate, "http 400 (likely fake packets received)")
    body = resp.content[:4096]
    dpi_fake = any(p in body.lower() for p in DPI_FAKE_PATTERNS)
    content_ok = clen >= 300 and not dpi_fake
    if stub_err := _stub_body_err(req, resp, clen):
        return _resp_fail(resp, elapsed, clen, rate, stub_err)
    small_206 = resp.status_code == 206 and clen < 300 and not req.googlevideo
    tls_bypass_proof = (
        req.protocol != "http" and resp.status_code in _TLS_BYPASS_PROOF_STATUSES
    )
    small_body_ok = (not dpi_fake) and (
        resp.status_code in _SMALL_BODY_STATUSES or small_206 or tls_bypass_proof
    )
    status_ok = (
        200 <= resp.status_code < 400
        if req.protocol == "http"
        else (200 <= resp.status_code < 400 or resp.status_code in _TLS_BYPASS_PROOF_STATUSES)
    )
    throttled = False
    success = False
    if status_ok and (content_ok or small_body_ok) and not dpi_fake:
        rate_ok, throttled, rate = _classify_throughput(clen, elapsed, small_body_ok=small_body_ok)
        success = rate_ok
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


def run_curl_probe(req: CurlProbeRequest, *, _gv_hop: int = 0) -> CurlProbeResult:
    """Execute one curl probe (hostfakesplit / generic TLS / googlevideo chunk)."""
    res = _run_curl_probe_inner(req, _gv_hop=_gv_hop)
    if not res.resolve_name and req.resolve_name:
        res.resolve_name = req.resolve_name
    return res


def _run_curl_probe_inner(
    req: CurlProbeRequest, *, _gv_hop: int = 0
) -> CurlProbeResult:
    """Execute one curl probe (hostfakesplit / generic TLS / googlevideo chunk)."""
    import time

    start = time.perf_counter()
    session = _open_curl_session(req)
    if isinstance(session, CurlProbeResult):
        session.latency_ms = (time.perf_counter() - start) * 1000
        return session
    url_scheme = "http" if req.protocol == "http" else "https"
    try:
        with session:
            url = req.curl_url if req.curl_url else f"{url_scheme}://{req.domain}"
            curl_timeout = min(req.timeout, 8.0) if req.googlevideo else req.timeout
            resp = session.get(url, timeout=curl_timeout, **_curl_proxy_kwargs(req))
    except RequestsError as e:
        msg = str(e)
        return CurlProbeResult(
            latency_ms=(time.perf_counter() - start) * 1000,
            error="timeout" if "Timeout" in msg else msg[:120],
        )
    except Exception as e:
        return CurlProbeResult(error=str(e)[:120])

    elapsed = max(time.perf_counter() - start, 0.001)
    clen = len(resp.content)
    loc = resp.headers.get("Location") or resp.headers.get("location") or ""
    server_hdr = resp.headers.get("Server") or resp.headers.get("server") or ""
    if cdn := _classify_google_cdn(req, resp, clen, elapsed, loc, server_hdr):
        return cdn
    resolve_name = (req.resolve_name or req.domain).split("/")[0]
    redirect_domain = "googlevideo.com" if req.googlevideo else resolve_name.lower()
    redirect_err = classify_http_status(redirect_domain, resp.status_code, loc)
    follow = (
        _googlevideo_follow_request(req, loc)
        if (
            req.googlevideo
            and _gv_hop == 0
            and resp.status_code in {301, 302, 303, 307, 308}
            and not redirect_err
        )
        else None
    )
    if follow:
        return run_curl_probe(follow, _gv_hop=1)
    return _classify_generic(req, resp, elapsed, clen, loc, redirect_err)


MAX_CURL_REPEATS = 10  # Discovery cap


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
    settle_slack: float | None = None,
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
    if settle_slack is None:
        settle_slack = WALL_SLACK
    return per_wave * waves + max(0.5, float(settle_slack))


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


# Stream stall / QoS probe (not on the hot path)

# Stall windows: bytes-read thresholds that a TSPU stream buffer may stall at.
# Order matters — first threshold reached without further progress wins.
STALL_WINDOWS = (7 * 1024, 16 * 1024, 42 * 1024, 64 * 1024)
STALL_IDLE_SEC = 1.5  # no progress for this long → stall
THROTTLE_PLATEAU_BPS = 64 * 1024  # sustained < 64 Kbps → BANDWIDTH_THROTTLED
STALL_MIN_TOTAL = 2 * 1024  # ignore stall before at least this much arrived


@dataclass
class StreamTriageResult:
    """Result of the streaming stall/QoS probe."""

    phase: str = "unknown"
    http_code: int = 0
    total_bytes: int = 0
    read_rate_bps: float = 0.0
    stall_at_bytes: int | None = None
    stall_seconds: float = 0.0
    plateau_bps: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "http_code": self.http_code,
            "total_bytes": self.total_bytes,
            "read_rate_bps": round(self.read_rate_bps, 1),
            "stall_at_bytes": self.stall_at_bytes,
            "stall_seconds": round(self.stall_seconds, 2),
            "plateau_bps": round(self.plateau_bps, 1),
            "error": self.error,
        }


def run_stream_triage_probe(
    url: str,
    *,
    timeout: float = 8.0,
    range_header: str = "bytes=0-262143",
    impersonate: str = "chrome124",
    resolved_ip: str | None = None,
) -> StreamTriageResult:
    """Stream a large Range request and measure per-window progress.

    Detects:
    - ``data_stall_<N>k`` — bytes stopped advancing after reaching ~N KB
      (TSPU stream-buffer stall). Maps to FailPhase.DATA_STALL_*.
    - ``bandwidth_throttled`` — sustained read rate below the plateau.
    - ``pass`` — stream completed / made steady progress.
    Uses ``stream=True`` + ``iter_content`` with wall-clock per-chunk timing.
    NOT used in the strategy hot path (that keeps buffered ``resp.content``).
    """
    import time

    start = time.perf_counter()
    res = StreamTriageResult()
    # thresholds already passed, in order
    passed: list[tuple[int, float]] = []  # (bytes, when)
    total = 0
    last_progress = time.perf_counter()
    window_start = time.perf_counter()
    window_bytes = 0
    peak_window_bps = 0.0

    try:
        with curl_cffi.Session(impersonate=impersonate, allow_redirects=False) as session:
            if resolved_ip:
                host = url.split("/")[2].split(":")[0]
                session.curl.setopt(CURLOPT_RESOLVE, [f"{host}:443:{resolved_ip}"])
            # curl_cffi >=0.15 Response has no context-manager protocol — use
            # plain get() + iter_content and close explicitly.
            resp = session.get(
                url,
                headers={"Range": range_header},
                timeout=timeout,
                stream=True,
            )
            res.http_code = resp.status_code
            for chunk in resp.iter_content(chunk_size=4096):
                if not chunk:
                    continue
                now = time.perf_counter()
                total += len(chunk)
                window_bytes += len(chunk)
                window_elapsed = now - window_start
                if window_elapsed >= 0.5:
                    wbps = window_bytes / window_elapsed
                    peak_window_bps = max(peak_window_bps, wbps)
                    window_start = now
                    window_bytes = 0
                # record which windows we have passed
                for w in STALL_WINDOWS:
                    if total >= w and not any(wb[0] == w for wb in passed):
                        passed.append((w, now))
                last_progress = now
            resp.close()
    except RequestsError as e:
        res.error = str(e)[:150]
        res.total_bytes = total

    elapsed = max(time.perf_counter() - start, 0.001)
    res.read_rate_bps = total / elapsed
    res.total_bytes = total
    res.plateau_bps = peak_window_bps

    # Stall detection: stopped advancing at some window boundary.
    stall_secs = time.perf_counter() - last_progress
    if stall_secs >= STALL_IDLE_SEC and total >= STALL_MIN_TOTAL:
        res.stall_seconds = stall_secs
        # find the highest passed window that we stalled at
        stalled = [wb[0] for wb in passed]
        if 64 * 1024 in stalled:
            res.stall_at_bytes = 64 * 1024
            res.phase = "data_stall_64k_plus"
        elif 42 * 1024 in stalled:
            res.stall_at_bytes = 42 * 1024
            res.phase = "data_stall_42k"
        elif 16 * 1024 in stalled:
            res.stall_at_bytes = 16 * 1024
            res.phase = "data_stall_16k"
        elif 7 * 1024 in stalled:
            res.stall_at_bytes = 7 * 1024
            res.phase = "data_stall_7k"
        else:
            res.stall_at_bytes = total
            res.phase = "data_stall_tls_cert" if total < 7 * 1024 else "data_stall_first_req"
    elif res.error and "timeout" in res.error.lower() and total < STALL_MIN_TOTAL:
        res.phase = "tls_silent_drop_after_sni"
    elif peak_window_bps and peak_window_bps < THROTTLE_PLATEAU_BPS and total >= STALL_MIN_TOTAL:
        res.phase = "bandwidth_throttled"
    elif total > 0:
        res.phase = "pass"
    else:
        res.phase = "unknown"
    return res


# TLS fingerprint probe (several impersonation profiles)

TLS_PROFILES = ("chrome124", "firefox_120", "safari_17", None)
PQ_CLIENTHELLO_MTU = 1400  # ClientHello larger than this → 2 TCP segments

# Empirical ClientHello sizes per impersonation profile (post-quantum aware
# browsers carry Kyber/ML-KEM key shares → 1500-1800+ B; compact stacks < 1 KB).
TLS_PROFILE_CH_LEN = {
    "chrome124": 1740,
    "firefox_120": 780,
    "safari_17": 940,
    "bare_curl": 260,
}


@dataclass
class TlsProfileResult:
    """Baseline probe result across TLS impersonation profiles."""

    profile_pass: dict[str, bool] = field(default_factory=dict)  # profile→ok
    client_hello_len: int = 0
    is_fingerprint_blocked: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "profile_pass": dict(self.profile_pass),
            "client_hello_len": self.client_hello_len,
            "is_fingerprint_blocked": self.is_fingerprint_blocked,
            "error": self.error,
        }


def run_tls_profile_probe(
    domain: str,
    *,
    timeout: float = 5.0,
    resolved_ip: str | None = None,
) -> TlsProfileResult:
    """Probe a domain with contrasting TLS impersonation profiles.

    chrome124 (heavy, Kyber/GREASE, big ClientHello) vs firefox_120 (compact)
    vs safari_17 (Apple stack) vs bare curl (no browser mask). Detects whether
    DPI blocks a specific fingerprint (is_fingerprint_blocked) and estimates
    the ClientHello size (post-quantum awareness).
    """
    res = TlsProfileResult()
    for profile in TLS_PROFILES:
        ok = _probe_tls_profile(domain, profile, timeout=timeout, resolved_ip=resolved_ip)
        label = profile or "bare_curl"
        res.profile_pass[label] = ok
    # Estimate ClientHello size from the heaviest profile that succeeded
    # (post-quantum → large CH). Fall back to chrome's nominal size.
    for profile in ("chrome124", "safari_17", "firefox_120", "bare_curl"):
        if res.profile_pass.get(profile, False):
            res.client_hello_len = TLS_PROFILE_CH_LEN.get(profile, 0)
            break
    else:
        res.client_hello_len = TLS_PROFILE_CH_LEN.get("chrome124", 0)
    # Fingerprint-blocked: chrome fails but a lighter browser passes.
    chrome_ok = res.profile_pass.get("chrome124", False)
    others_ok = any(res.profile_pass.get(p, False) for p in ("firefox_120", "safari_17"))
    bare_ok = res.profile_pass.get("bare_curl", False)
    if not chrome_ok and (others_ok or bare_ok):
        res.is_fingerprint_blocked = True
    return res


def _probe_tls_profile(
    domain: str,
    impersonate: str | None,
    *,
    timeout: float,
    resolved_ip: str | None,
) -> bool:
    """One TLS GET; returns True on HTTP success (200/redirect)."""
    from curl_cffi.requests import Session

    kw: dict = {}
    if impersonate:
        kw["impersonate"] = impersonate
    try:
        with Session(allow_redirects=False, **kw) as session:
            if resolved_ip:
                session.curl.setopt(CURLOPT_RESOLVE, [f"{domain}:443:{resolved_ip}"])
            resp = session.get(f"https://{domain}", timeout=timeout)
            return resp.status_code in (200, 204, 301, 302, 307, 308)
    except Exception:  # noqa: BLE001 — baseline probe must never raise
        return False
