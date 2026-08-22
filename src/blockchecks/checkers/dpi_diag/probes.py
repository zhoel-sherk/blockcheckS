"""Injectable probes: SNI whitelist, FAT keepalive, l4-25, Siberian, CIDR-WL."""

from __future__ import annotations

import os
import socket
import ssl
import time
import uuid
from collections.abc import Callable
from typing import Any

from curl_cffi.requests import RequestsError

SNI_CANDIDATES: tuple[str, ...] = (
    "ya.ru",
    "yandex.ru",
    "vk.com",
    "ok.ru",
    "mail.ru",
    "ozon.ru",
    "wildberries.ru",
    "gosuslugi.ru",
    "sberbank.ru",
    "tinkoff.ru",
)
_CIDR_WL: tuple[str, ...] = ("https://ya.ru/", "https://vk.com/")
_CIDR_OPEN: tuple[str, ...] = ("https://github.com/", "https://www.wikipedia.org/")

HeadFn = Callable[[str, float], bool]
ResolveGetFn = Callable[[str, str, float], bool]
HandshakeFn = Callable[[str, str, float], bool]


def _curl_head_ok(url: str, timeout: float) -> bool:
    from curl_cffi import Session

    with Session(impersonate="chrome") as s:
        r = s.head(url, timeout=timeout, allow_redirects=False)
    return r.status_code < 500


def _curl_sni_on_ip(sni: str, ip: str, timeout: float) -> bool:
    from curl_cffi import Session

    from blockchecks.checkers.dns_secure import apply_curl_resolve

    with Session(impersonate="chrome") as s:
        apply_curl_resolve(s, sni, ip)
        r = s.get(f"https://{sni}/", timeout=timeout, allow_redirects=False)
    return r.status_code in (200, 204, 301, 302, 303, 307, 308)


def probe_sni_whitelist(
    blocked_ip: str,
    *,
    timeout: float = 4.0,
    candidates: tuple[str, ...] = SNI_CANDIDATES,
    get_fn: ResolveGetFn | None = None,
) -> list[str]:
    """SNIs that complete TLS/HTTP when pinned to *blocked_ip* (DWC / dpi-detector)."""
    getter = get_fn or _curl_sni_on_ip

    def _hit(sni: str) -> bool:
        try:
            return getter(sni, blocked_ip, timeout)
        except (RequestsError, OSError, TimeoutError):
            return False

    return [sni for sni in candidates if _hit(sni)]


def probe_fat_keepalive(
    host: str,
    ip: str,
    *,
    timeout: float = 4.0,
    chunks: int = 8,
    pad: int = 4000,
    request_fn: Callable[[int], bool] | None = None,
) -> dict[str, Any]:
    """Request-side TCP16: keepalive HEADs with growing X-Pad (dpi-detector FAT)."""
    if request_fn is not None:
        stalled = next((i for i in range(chunks) if not request_fn(i)), None)
        if stalled == 0:
            return {"ok": True, "detected": False, "stall_at_bytes": None, "baseline": False}
        return {
            "ok": stalled is None,
            "detected": stalled is not None,
            "stall_at_bytes": None if stalled is None else stalled * pad,
        }

    try:
        return _fat_session_heads(host, ip, timeout, chunks, pad)
    except (RequestsError, OSError, TimeoutError) as exc:
        return _fat_fail(0, pad, exc)


def _fat_session_heads(host: str, ip: str, timeout: float, chunks: int, pad: int) -> dict[str, Any]:
    from curl_cffi import Session

    from blockchecks.checkers.dns_secure import apply_curl_resolve

    with Session(impersonate="chrome") as s:
        apply_curl_resolve(s, host, ip)
        for i in range(chunks):
            headers = {"Connection": "keep-alive"}
            if i:
                headers["X-Pad"] = "x" * pad
            try:
                s.head(f"https://{host}/", timeout=timeout, headers=headers)
            except (RequestsError, OSError, TimeoutError) as exc:
                return _fat_fail(i, pad, exc)
    return {"ok": True, "detected": False, "stall_at_bytes": None}


def _fat_fail(i: int, pad: int, exc: BaseException) -> dict[str, Any]:
    """SNI-drop on the first HEAD is not FAT; later stalls are."""
    if i == 0:
        return {
            "ok": True,
            "detected": False,
            "stall_at_bytes": None,
            "baseline": False,
            "error": str(exc),
        }
    return {"ok": False, "detected": True, "stall_at_bytes": i * pad, "error": str(exc)}


def probe_l4_25(
    host: str,
    *,
    ip: str = "",
    total: int = 48,
    chunk: int = 2,
    delay_ms: int = 0,
    timeout: float = 3.0,
    send_fn: Callable[[bytes], None] | None = None,
) -> dict[str, Any]:
    """Packet-budget probe: tiny TLS Application Data chunks (dpi-ch l4-25)."""
    body = os.urandom(max(0, total))
    if send_fn is not None:
        for i in range(0, len(body), chunk):
            send_fn(body[i : i + chunk])
        return {"ok": True, "detected": False, "packets": (len(body) + chunk - 1) // chunk}

    try:
        raw = socket.create_connection((ip or host, 443), timeout=timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock = ssl._create_unverified_context().wrap_socket(raw, server_hostname=host)
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        return {"ok": True, "detected": False, "packets": 0, "error": str(exc)}
    packets = 0
    try:
        for i in range(0, len(body), chunk):
            sock.sendall(body[i : i + chunk])
            packets += 1
            if delay_ms:
                time.sleep(delay_ms / 1000)
        sock.settimeout(timeout)
        sock.recv(64)
        return {"ok": True, "detected": False, "packets": packets}
    except (TimeoutError, OSError, ssl.SSLError):
        return {"ok": False, "detected": packets > 0, "packets": packets}
    finally:
        sock.close()


def probe_siberian(
    host: str,
    ip: str,
    *,
    n: int = 4,
    timeout: float = 3.0,
    handshake_fn: HandshakeFn | None = None,
) -> bool | None:
    """True if N random-SNI handshakes fail while a control handshake succeeds."""
    hs = handshake_fn or _tls_handshake
    alpha = [hs(f"{uuid.uuid4().hex[:12]}.invalid", ip, timeout) for _ in range(n)]
    beta = hs(host, ip, timeout)
    if beta and not any(alpha):
        return True
    if beta and all(alpha):
        return False
    return None


def _tls_handshake(sni: str, ip: str, timeout: float) -> bool:
    try:
        raw = socket.create_connection((ip, 443), timeout=timeout)
        ctx = ssl._create_unverified_context()
        ctx.wrap_socket(raw, server_hostname=sni).close()
        return True
    except (OSError, ssl.SSLError, TimeoutError):
        return False


def probe_cidr_whitelist(*, timeout: float = 4.0, head_fn: HeadFn | None = None) -> bool | None:
    """True when whitelist endpoints work and open internet does not (dpi-ch)."""
    head = head_fn or _curl_head_ok
    try:
        wl = [head(u, timeout) for u in _CIDR_WL]
        open_net = [head(u, timeout) for u in _CIDR_OPEN]
    except (RequestsError, OSError, TimeoutError):
        return None
    if any(wl) and not any(open_net):
        return True
    if any(open_net):
        return False
    return None
