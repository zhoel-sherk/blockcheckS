"""Compare UDP DNS with DoH, then pre-resolve names for curl.
Builds a per-run cache and can pick a working DoH server.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from itertools import product

import curl_cffi
from curl_cffi.requests import RequestsError

from blockchecks.engine.config import (
    DEFAULT_DOH_SERVER,
    DNS_CACHE_TTL,
    DOH_SERVERS,
    UDP_DNS_SERVERS,
)

log = logging.getLogger(__name__)


# libcurl CURLOPT_RESOLVE (for tcp_tls helper)
try:
    CURLOPT_RESOLVE = curl_cffi.CurlOpt.RESOLVE
except AttributeError:
    CURLOPT_RESOLVE = 10203


def _domain_to_dns_ascii(domain: str) -> str:
    """IDNA/punycode for wire DNS and DoH."""
    text = domain.strip().rstrip(".")
    if not text:
        return text
    try:
        return text.encode("idna").decode("ascii")
    except UnicodeError:
        return text.encode("ascii").decode("ascii")


def _build_dns_query(domain: str, qtype: int = 1) -> bytes:
    """Build a DNS query (A record by default)."""
    header = struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in _domain_to_dns_ascii(domain).split("."):
        if not part:
            continue
        label = part.encode("ascii")
        qname += bytes([len(label)]) + label
    qname += b"\x00"
    question = qname + struct.pack("!HH", qtype, 1)
    return header + question


def _skip_dns_name(data: bytes, offset: int) -> int:
    """Advance past a DNS name (RFC 1035), including compression pointers.

    A pointer (top two bits set) terminates the name at those two bytes — do
    not keep walking as if a length prefix followed. Uncompressed labels end
    at a zero octet.
    """
    for _ in range(128):
        if offset >= len(data):
            return offset
        label = data[offset]
        if label == 0:
            return offset + 1
        if label & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + (label & 0x3F)
    return offset


def _parse_dns_response(data: bytes) -> list[str]:
    """Parse DNS response, extract A record IPs."""
    if len(data) < 12:
        return []
    qdcount, ancount = struct.unpack("!HH", data[4:8])
    if ancount == 0:
        return []
    offset = 12
    for _ in range(qdcount):
        offset = _skip_dns_name(data, offset)
        offset += 4  # QTYPE + QCLASS
    ips: list[str] = []
    for _ in range(min(ancount, 20)):
        offset = _skip_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _, _, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4 and offset + 4 <= len(data):
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
                f"{doh_url}?name={_domain_to_dns_ascii(domain)}&type=A",
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


# Reserved / sinkhole / RKN-stub IP networks (DNS poisoning signatures).
_SINKHOLE_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("240.0.0.0/4"),
    # RFC1918 private (a poisoned answer should never be a public A record)
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # IPv6 loopback / unspecified / documentation / ULA
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("fc00::/7"),
]


def _sinkhole_ip(ips: list[str]) -> list[str]:
    """Return the IPs from *ips* that fall into sinkhole/bogon networks."""
    bad: list[str] = []
    for raw in ips or []:
        try:
            ip = ipaddress.ip_address(raw.strip())
        except ValueError:
            continue
        if any(ip in net for net in _SINKHOLE_NETS):
            bad.append(str(ip))
    return bad


# Published unicast prefixes of major CDNs. Disjoint UDP vs DoH answers inside
# the same family are anycast/geo-DNS, not hijacking.
_CDN_NETS: tuple[tuple[str, tuple[ipaddress.IPv4Network, ...]], ...] = tuple(
    (name, tuple(ipaddress.ip_network(n) for n in cidrs))
    for name, cidrs in (
        (
            "cloudflare",
            (
                "1.0.0.0/24",
                "1.1.1.0/24",
                "104.16.0.0/12",
                "108.162.192.0/18",
                "141.101.64.0/18",
                "162.158.0.0/15",
                "172.64.0.0/13",
                "173.245.48.0/20",
                "188.114.0.0/16",
                "190.93.240.0/20",
                "197.234.240.0/22",
                "198.41.128.0/17",
            ),
        ),
        (
            "google",
            (
                "8.8.4.0/24",
                "8.8.8.0/24",
                "64.233.160.0/19",
                "66.102.0.0/20",
                "72.14.192.0/18",
                "74.125.0.0/16",
                "108.177.0.0/17",
                "142.250.0.0/15",
                "172.217.0.0/16",
                "209.85.128.0/17",
                "216.58.192.0/19",
            ),
        ),
        ("fastly", ("151.101.0.0/16", "199.232.0.0/16")),
        (
            "akamai",
            ("2.16.0.0/13", "23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13"),
        ),
        (
            "amazon",
            (
                "13.32.0.0/15",
                "13.224.0.0/12",
                "52.84.0.0/15",
                "54.230.0.0/16",
                "99.84.0.0/16",
                "143.204.0.0/16",
            ),
        ),
        (
            "discord",
            (
                "35.207.0.0/16",
                "35.212.0.0/16",
                "35.213.0.0/16",
                "35.215.0.0/16",
                "35.217.0.0/16",
            ),
        ),
    )
)


def _cdn_family(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    return next((name for name, nets in _CDN_NETS if any(addr in net for net in nets)), None)


def _same_slash16(a: str, b: str) -> bool:
    try:
        ia, ib = ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())
    except ValueError:
        return False
    return ia.version == ib.version == 4 and (int(ia) >> 16) == (int(ib) >> 16)


def _anycast_equivalent(udp_ips: list[str], doh_ips: list[str]) -> bool:
    """True when disjoint public answers still look like CDN/anycast, not hijack."""
    if not udp_ips or not doh_ips:
        return False
    udp_fam = {f for ip in udp_ips if (f := _cdn_family(ip))}
    doh_fam = {f for ip in doh_ips if (f := _cdn_family(ip))}
    if udp_fam & doh_fam:
        return True
    return any(_same_slash16(u, d) for u, d in product(udp_ips, doh_ips))


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

    # Sinkhole / bogon detection: even an "overlapping" UDP+DoH answer that
    # resolves to loopback / reserved / RKN stub subnets is DNS poisoning.
    bad_udp = _sinkhole_ip(result.udp_ips)
    bad_doh = _sinkhole_ip(result.doh_ips)
    if bad_udp or bad_doh:
        result.tampering_detected = True
        result.verdict = "sinkhole"
        result.description = "Sinkhole/bogon DNS answer: " + ", ".join(bad_udp or bad_doh)
        return result

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
            elif _anycast_equivalent(result.udp_ips, result.doh_ips):
                result.verdict = "ok"
                result.description = "UDP and DoH differ (CDN/anycast)"
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
    """Print the UDP vs DoH comparison table."""
    log.info("\n  DNS audit (UDP vs DoH)")
    log.info("%s", f"  {'-' * 72}")
    log.info("%s", f"  {'Domain':<24}{'UDP':<22}{'DoH':<22}{'Verdict'}")
    log.info("%s", f"  {'-' * 72}")
    for r in results:
        udp = ", ".join(r.udp_ips[:2]) if r.udp_ips else (r.udp_error or "--")
        doh = ", ".join(r.doh_ips[:2]) if r.doh_ips else (r.doh_error or "--")
        tag = "OK" if not r.tampering_detected else "TAMPERED"
        log.info("%s", f"  {r.domain:<24}{udp:<22}{doh:<22}{tag}")
    tampered = sum(1 for r in results if r.tampering_detected)
    log.info("%s", f"  {'-' * 72}")
    log.info("%s", f"  Tampered: {tampered}/{len(results)}")
    for r in results:
        if r.tampering_detected:
            log.info("%s", f"    {r.domain}: {r.description}")


def has_dns_hijack(results: list[DnsAuditResult]) -> bool:
    return any(r.tampering_detected for r in results)


@dataclass
class DnsRunCache:
    """Per-batch DoH cache with optional hosts-file IP pins.

    ``_pins`` maps domain -> pinned IP (hosts-analog file or auto-pin). When a
    pin exists it is returned first from ``resolve`` / ``primary_ip``, so the
    DoH order (which some ISPs can throttle per-IP) no longer decides the probe
    target. ``set_pins`` refreshes from file/auto-pin at startup.
    """

    ttl_sec: float = DNS_CACHE_TTL
    doh_server: str = ""
    _entries: dict[str, tuple[list[str], float]] = field(default_factory=dict)
    _pins: dict[str, str] = field(default_factory=dict)

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

    # IP pin file

    def set_pins(self, pins: dict[str, str]) -> None:
        """Replace the domain->IP pin map (empty values removed)."""
        self._pins = {d: ip for d, ip in pins.items() if ip}

    def add_pin(self, domain: str, ip: str) -> None:
        if ip:
            self._pins[domain] = ip

    def pinned_ip(self, domain: str) -> str | None:
        return self._pins.get(domain)

    def pins(self) -> dict[str, str]:
        return dict(self._pins)

    def domains(self) -> list[str]:
        """Domains currently cached (for auto-pin iteration)."""
        return list(self._entries.keys())

    def clear(self) -> None:
        self._entries.clear()

    def _pinned_first(self, domain: str, ips: list[str]) -> list[str]:
        pin = self._pins.get(domain)
        if pin and pin not in ips:
            ips = [pin, *ips]
        elif pin and ips and ips[0] != pin:
            ips = [pin, *[i for i in ips if i != pin]]
        return ips

    def resolve(self, domain: str, doh_url: str | None = None, timeout: float = 5.0) -> list[str]:
        cached = self.get(domain)
        if cached:
            return self._pinned_first(domain, cached)
        url = doh_url or self.doh_server or pick_working_doh(timeout=timeout)
        if not self.doh_server:
            self.doh_server = url
        ips, err, _ = doh_query(domain, url, timeout=timeout)
        if ips and not err:
            self.set(domain, ips)
            return self._pinned_first(domain, ips)
        # Rotate DoH server on failure (skip the one that just failed)
        for alt, _name in DOH_SERVERS:
            if alt == url:
                continue
            ips2, err2, _ = doh_query(domain, alt, timeout=timeout)
            if ips2 and not err2:
                self.doh_server = alt
                self.set(domain, ips2)
                return self._pinned_first(domain, ips2)
        # Fallback: verified DoH records cached in data_block (anti-hijack).
        # When live DoH is blocked (doh_blocked / no_resolution), trust the last
        # known-good IPs instead of tampered UDP answers.
        cached_ips = _data_block_dns_ips(domain)
        if cached_ips:
            self.set(domain, cached_ips)
            return self._pinned_first(domain, cached_ips)
        return self._pinned_first(domain, ips)

    def primary_ip(self, domain: str, doh_url: str | None = None) -> str | None:
        ips = self.resolve(domain, doh_url=doh_url)
        return ips[0] if ips else None

    def candidates(self, domain: str) -> list[str]:
        """DoH/known IPs for *domain*, *without* pin-priority (auto-pin probes)."""
        cached = self.get(domain)
        if cached:
            return list(cached)
        try:
            return list(self.resolve(domain))
        except Exception:
            return []

    def prime(self, domains: list[str], doh_url: str | None = None) -> None:
        """Pre-resolve all domains for a batch run."""
        url = doh_url or pick_working_doh()
        self.doh_server = url
        for domain in domains:
            self.resolve(domain, doh_url=url)


def _data_block_dns_ips(domain: str) -> list[str]:
    """Return fresh cached IPs for *domain* from data_block/dns.db (best-effort)."""
    try:
        from blockchecks.data_block.provider import get_provider_dir
        from blockchecks.data_block.store import ProviderStore

        store = ProviderStore(get_provider_dir(allow_detect=False))
        if not store.dns_db.is_file():
            return []
        recs = store.load_dns_records_sync()
        value = recs.get(domain)
        if isinstance(value, tuple):
            return list(value[0] or [])
        return list(value or [])
    except Exception:
        return []


def apply_curl_resolve(session: curl_cffi.Session, domain: str, ip: str, port: int = 443) -> None:
    """Set CURLOPT_RESOLVE so SNI stays the hostname."""
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
    """UDP vs DoH check plus cache priming. Returns (cache, results, exit_code)."""
    if not secure_dns:
        return None, [], 0

    url = doh_server or pick_working_doh(timeout=timeout)
    cache = DnsRunCache(doh_server=url)
    results: list[DnsAuditResult] = []
    if not skip_audit:
        results = audit_domains(domains, doh_url=url, timeout=timeout)
        print_audit_table(results)
        if has_dns_hijack(results) and not allow_hijack:
            log.error(
                "\n  ERROR: DNS hijack detected. Use --allow-dns-hijack to continue "
                "or --no-secure-dns to disable DoH pre-resolve."
            )
            return cache, results, 1

    cache.prime(domains, doh_url=url)
    return cache, results, 0
