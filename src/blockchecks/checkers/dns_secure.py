"""Secure DNS — UDP vs DoH audit and DoH pre-resolve for curl tests.

Ported from dpi-tester ``dns_checker.py``; extended for blockcheckS runtime:
``doh_resolve``, per-run cache, startup audit, and ``pick_working_doh``.
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, field

import curl_cffi
from curl_cffi.requests import RequestsError

from blockchecks.engine.config import (
    DEFAULT_DOH_SERVER,
    DNS_CACHE_TTL,
    DOH_SERVERS,
    UDP_DNS_SERVERS,
)

# libcurl CURLOPT_RESOLVE (for tcp_tls helper)
try:
    CURLOPT_RESOLVE = curl_cffi.CurlOpt.RESOLVE
except AttributeError:
    CURLOPT_RESOLVE = 10203


def _build_dns_query(domain: str, qtype: int = 1) -> bytes:
    """Build a DNS query (A record by default)."""
    header = struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in domain.encode("ascii").split(b"."):
        qname += bytes([len(part)]) + part
    qname += b"\x00"
    question = qname + struct.pack("!HH", qtype, 1)
    return header + question


def _parse_dns_response(data: bytes) -> list[str]:
    """Parse DNS response, extract A record IPs."""
    if len(data) < 12:
        return []
    ancount = struct.unpack("!H", data[6:8])[0]
    if ancount == 0:
        return []
    ips: list[str] = []
    offset = 12
    while offset < len(data) and data[offset] != 0:
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
            break
        offset += data[offset] + 1
    offset += 5  # null + type + class
    for _ in range(min(ancount, 20)):
        if offset + 12 > len(data):
            break
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                if data[offset] & 0xC0 == 0xC0:
                    offset += 2
                    break
                offset += data[offset] + 1
            offset += 1
        if offset + 10 > len(data):
            break
        rtype, _, _, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4:
            ips.append(".".join(str(b) for b in data[offset : offset + 4]))
        offset += rdlength
    return ips


def udp_resolve(
    domain: str,
    server: str = "8.8.8.8",
    port: int = 53,
    timeout: float = 3.0,
) -> tuple[list[str], str, float]:
    """Resolve domain via UDP DNS. Returns (ips, error, latency_ms)."""
    start = time.perf_counter()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_dns_query(domain), (server, port))
        data, _ = sock.recvfrom(512)
        return _parse_dns_response(data), "", (time.perf_counter() - start) * 1000
    except TimeoutError:
        return [], "timeout", timeout * 1000
    except OSError as e:
        return [], str(e), (time.perf_counter() - start) * 1000
    finally:
        if sock:
            sock.close()


def _doh_json_query(
    domain: str, doh_url: str, timeout: float = 5.0
) -> tuple[list[str], str, float]:
    """DoH via JSON API (application/dns-json)."""
    start = time.perf_counter()
    try:
        with curl_cffi.Session(impersonate="chrome124") as session:
            resp = session.get(
                f"{doh_url}?name={domain}&type=A",
                timeout=timeout,
                headers={"Accept": "application/dns-json"},
            )
        elapsed = (time.perf_counter() - start) * 1000
        data = resp.json()
        ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
        return ips, "", elapsed
    except RequestsError as e:
        return [], str(e)[:80], (time.perf_counter() - start) * 1000
    except Exception as e:
        return [], str(e)[:80], (time.perf_counter() - start) * 1000


def _doh_wire_query(
    domain: str, doh_url: str, timeout: float = 5.0
) -> tuple[list[str], str, float]:
    """DoH via binary wire format (POST application/dns-message)."""
    start = time.perf_counter()
    try:
        wire = _build_dns_query(domain)
        with curl_cffi.Session(impersonate="chrome124") as session:
            resp = session.post(
                doh_url,
                data=wire,
                timeout=timeout,
                headers={
                    "Accept": "application/dns-message",
                    "Content-Type": "application/dns-message",
                },
            )
        elapsed = (time.perf_counter() - start) * 1000
        return _parse_dns_response(resp.content), "", elapsed
    except RequestsError as e:
        return [], str(e)[:80], (time.perf_counter() - start) * 1000
    except Exception as e:
        return [], str(e)[:80], (time.perf_counter() - start) * 1000


def doh_query(domain: str, doh_url: str, timeout: float = 5.0) -> tuple[list[str], str, float]:
    """DoH resolve: JSON first, wire POST fallback."""
    ips, err, lat = _doh_json_query(domain, doh_url, timeout)
    if ips:
        return ips, "", lat
    ips2, err2, lat2 = _doh_wire_query(domain, doh_url, timeout)
    if ips2:
        return ips2, "", lat2
    return [], err or err2, lat2


def pick_working_doh(
    servers: list[tuple[str, str]] | None = None,
    probe_domain: str = "cloudflare.com",
    timeout: float = 3.0,
) -> str:
    """Return first working DoH server URL (blockcheck2 ``doh_find_working``)."""
    if DEFAULT_DOH_SERVER:
        ips, err, _ = doh_query(probe_domain, DEFAULT_DOH_SERVER, timeout)
        if ips and not err:
            return DEFAULT_DOH_SERVER
    for url, _name in servers or DOH_SERVERS:
        ips, err, _ = doh_query(probe_domain, url, timeout)
        if ips and not err:
            return url
    return (servers or DOH_SERVERS)[0][0]


@dataclass
class DnsAuditResult:
    domain: str = ""
    udp_ips: list[str] = field(default_factory=list)
    doh_ips: list[str] = field(default_factory=list)
    tampering_detected: bool = False
    verdict: str = "ok"
    description: str = ""
    udp_latency_ms: float = 0.0
    doh_latency_ms: float = 0.0
    doh_server: str = ""
    udp_error: str | None = None
    doh_error: str | None = None


def audit_domain(
    domain: str,
    doh_url: str | None = None,
    timeout: float = 5.0,
) -> DnsAuditResult:
    """Compare UDP vs DoH for one domain."""
    result = DnsAuditResult(domain=domain)
    for server, _name in UDP_DNS_SERVERS:
        ips, err, lat = udp_resolve(domain, server, timeout=timeout)
        if ips and not err:
            result.udp_ips = ips
            result.udp_latency_ms = lat
            break
        if err:
            result.udp_error = err

    doh = doh_url or pick_working_doh(timeout=timeout)
    result.doh_server = doh
    ips, err, lat = doh_query(domain, doh, timeout=timeout)
    result.doh_ips = ips
    result.doh_latency_ms = lat
    if err:
        result.doh_error = err

    match (bool(result.udp_ips), bool(result.doh_ips)):
        case (False, False):
            result.verdict = "no_resolution"
            result.description = "No DNS resolution via UDP or DoH"
        case (True, False):
            result.verdict = "doh_blocked"
            result.description = "DoH blocked — cannot verify DNS integrity"
        case (False, True):
            result.verdict = "udp_blocked"
            result.description = "UDP DNS blocked"
        case _:
            udp_set = set(result.udp_ips)
            doh_set = set(result.doh_ips)
            if udp_set & doh_set:
                result.verdict = "ok"
                result.description = "UDP and DoH overlap — no hijack"
            else:
                result.tampering_detected = True
                result.verdict = "tampered"
                result.description = (
                    f"UDP {', '.join(result.udp_ips[:3])} vs DoH {', '.join(result.doh_ips[:3])}"
                )
    return result


def audit_domains(
    domains: list[str],
    doh_url: str | None = None,
    timeout: float = 5.0,
) -> list[DnsAuditResult]:
    """Audit multiple domains (startup preflight)."""
    doh = doh_url or pick_working_doh(timeout=timeout)
    return [audit_domain(d, doh_url=doh, timeout=timeout) for d in domains]


def print_audit_table(results: list[DnsAuditResult]) -> None:
    """Print tamper audit table (SD4)."""
    print("\n  DNS audit (UDP vs DoH)")
    print(f"  {'-' * 72}")
    print(f"  {'Domain':<24}{'UDP':<22}{'DoH':<22}{'Verdict'}")
    print(f"  {'-' * 72}")
    for r in results:
        udp = ", ".join(r.udp_ips[:2]) if r.udp_ips else (r.udp_error or "--")
        doh = ", ".join(r.doh_ips[:2]) if r.doh_ips else (r.doh_error or "--")
        tag = "OK" if not r.tampering_detected else "TAMPERED"
        print(f"  {r.domain:<24}{udp:<22}{doh:<22}{tag}")
    tampered = sum(1 for r in results if r.tampering_detected)
    print(f"  {'-' * 72}")
    print(f"  Tampered: {tampered}/{len(results)}")
    for r in results:
        if r.tampering_detected:
            print(f"    {r.domain}: {r.description}")


def has_dns_hijack(results: list[DnsAuditResult]) -> bool:
    return any(r.tampering_detected for r in results)


@dataclass
class DnsRunCache:
    """Per-batch DoH cache (SD6)."""

    ttl_sec: float = DNS_CACHE_TTL
    doh_server: str = ""
    _entries: dict[str, tuple[list[str], float]] = field(default_factory=dict)

    def get(self, domain: str) -> list[str] | None:
        row = self._entries.get(domain)
        if not row:
            return None
        ips, ts = row
        if time.time() - ts > self.ttl_sec:
            del self._entries[domain]
            return None
        return ips

    def set(self, domain: str, ips: list[str]) -> None:
        self._entries[domain] = (ips, time.time())

    def resolve(self, domain: str, doh_url: str | None = None, timeout: float = 5.0) -> list[str]:
        cached = self.get(domain)
        if cached:
            return cached
        url = doh_url or self.doh_server or pick_working_doh(timeout=timeout)
        if not self.doh_server:
            self.doh_server = url
        ips, err, _ = doh_query(domain, url, timeout=timeout)
        if ips and not err:
            self.set(domain, ips)
            return ips
        # H6: rotate DoH server on failure (skip the one that just failed)
        for alt, _name in DOH_SERVERS:
            if alt == url:
                continue
            ips2, err2, _ = doh_query(domain, alt, timeout=timeout)
            if ips2 and not err2:
                self.doh_server = alt
                self.set(domain, ips2)
                return ips2
        return ips

    def primary_ip(self, domain: str, doh_url: str | None = None) -> str | None:
        ips = self.resolve(domain, doh_url=doh_url)
        return ips[0] if ips else None

    def prime(self, domains: list[str], doh_url: str | None = None) -> None:
        """Pre-resolve all domains for a batch run."""
        url = doh_url or pick_working_doh()
        self.doh_server = url
        for domain in domains:
            self.resolve(domain, doh_url=url)


def apply_curl_resolve(session: curl_cffi.Session, domain: str, ip: str, port: int = 443) -> None:
    """Set CURLOPT_RESOLVE so SNI stays hostname (SD3)."""
    session.curl.setopt(CURLOPT_RESOLVE, [f"{domain}:{port}:{ip}"])


def prepare_dns_for_run(
    domains: list[str],
    *,
    secure_dns: bool = True,
    skip_audit: bool = False,
    allow_hijack: bool = False,
    doh_server: str | None = None,
    timeout: float = 5.0,
) -> tuple[DnsRunCache | None, list[DnsAuditResult], int]:
    """Startup DNS audit + cache priming (SD4). Returns (cache, results, exit_code)."""
    if not secure_dns:
        return None, [], 0

    url = doh_server or pick_working_doh(timeout=timeout)
    cache = DnsRunCache(doh_server=url)
    results: list[DnsAuditResult] = []
    if not skip_audit:
        results = audit_domains(domains, doh_url=url, timeout=timeout)
        print_audit_table(results)
        if has_dns_hijack(results) and not allow_hijack:
            print(
                "\n  ERROR: DNS hijack detected. Use --allow-dns-hijack to continue "
                "or --no-secure-dns to disable DoH pre-resolve."
            )
            return cache, results, 1

    cache.prime(domains, doh_url=url)
    return cache, results, 0
