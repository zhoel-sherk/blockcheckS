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
from urllib.parse import urlsplit

import curl_cffi
from curl_cffi.requests import RequestsError

from blockchecks.engine.config import (
    DEFAULT_DOH_SERVER,
    DNS_CACHE_TTL,
    DOH_BOOTSTRAP,
    DOH_SERVERS,
    UDP_DNS_SERVERS,
    UNTRUSTED_DOH_URLS,
)
from blockchecks.terminal import CYAN, GREEN, GREY, RED, RESET, YELLOW

log = logging.getLogger(__name__)


# libcurl CURLOPT_RESOLVE (for tcp_tls helper)
try:
    CURLOPT_RESOLVE = curl_cffi.CurlOpt.RESOLVE
except AttributeError:
    CURLOPT_RESOLVE = 10203


def doh_bootstrap_ip(doh_url: str) -> str | None:
    """Static bootstrap IP for a DoH URL hostname, or None if unknown."""
    host = (urlsplit(doh_url).hostname or "").lower()
    return DOH_BOOTSTRAP.get(host)


def _pin_doh_session(session: curl_cffi.Session, doh_url: str) -> None:
    """CURLOPT_RESOLVE so DoH TLS keeps SNI but skips hijacked system DNS."""
    if not (ip := doh_bootstrap_ip(doh_url)):
        return
    host = (urlsplit(doh_url).hostname or "").lower()
    apply_curl_resolve(session, host, ip)


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
            _pin_doh_session(session, doh_url)
            resp = session.get(
                f"{doh_url}?name={_domain_to_dns_ascii(domain)}&type=A",
                timeout=timeout,
                headers={"Accept": "application/dns-json"},
            )
        elapsed = (time.perf_counter() - start) * 1000
        if resp.status_code != 200:
            return [], f"http {resp.status_code}", elapsed
        data = resp.json()
        dns_status = data.get("Status")
        if dns_status != 0:
            return [], f"dns-json status {dns_status}", elapsed
        ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
        if not ips:
            return [], "no A records in dns-json", elapsed
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
            _pin_doh_session(session, doh_url)
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
        if resp.status_code != 200:
            return [], f"http {resp.status_code}", elapsed
        body = resp.content
        if len(body) >= 4 and (struct.unpack("!H", body[2:4])[0] & 0x0F) != 0:
            return [], f"dns-wire rcode {struct.unpack('!H', body[2:4])[0] & 0x0F}", elapsed
        ips = _parse_dns_response(body)
        if not ips:
            return [], "no A records in dns-wire", elapsed
        return ips, "", elapsed
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


def doh_is_trusted(url: str) -> bool:
    """False for resolvers whose answers must not drive cache/pin/verdict."""
    u = (url or "").rstrip("/")
    host = (urlsplit(u).hostname or "").lower()
    untrusted_hosts = {(urlsplit(x).hostname or "").lower() for x in UNTRUSTED_DOH_URLS}
    return u not in UNTRUSTED_DOH_URLS and host not in untrusted_hosts


def trusted_doh_servers(
    servers: list[tuple[str, str]] | None = None,
) -> list[tuple[str, str]]:
    return [(u, n) for u, n in (servers or DOH_SERVERS) if doh_is_trusted(u)]


def untrusted_doh_servers(
    servers: list[tuple[str, str]] | None = None,
) -> list[tuple[str, str]]:
    return [(u, n) for u, n in (servers or DOH_SERVERS) if not doh_is_trusted(u)]


def pick_working_doh(
    servers: list[tuple[str, str]] | None = None,
    probe_domain: str = "cloudflare.com",
    timeout: float = 3.0,
) -> str | None:
    """Return first working *trusted* DoH URL (blockcheck2 ``doh_find_working``)."""
    pool = trusted_doh_servers(servers) or trusted_doh_servers()
    candidates: list[str] = []
    if DEFAULT_DOH_SERVER and doh_is_trusted(DEFAULT_DOH_SERVER):
        candidates.append(DEFAULT_DOH_SERVER)
    candidates.extend(url for url, _name in pool if url not in candidates)
    for url in candidates:
        ips, err, _ = doh_query(probe_domain, url, timeout)
        if ips and not err:
            return url
        log.warning(
            "DoH probe failed for %s (%s): %s",
            url,
            probe_domain,
            err or "no A records",
        )
    log.warning(
        "No working trusted DoH resolver for %s (tried %d URL(s))",
        probe_domain,
        len(candidates),
    )
    return None


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
    udp_server: str = ""
    udp_name: str = ""
    udp_error: str | None = None
    doh_error: str | None = None
    untrusted_doh: dict[str, list[str]] = field(default_factory=dict)


# Reserved / sinkhole / RKN-stub IP networks (DNS poisoning signatures)
# live in presets/ipset/sinkhole.txt (see engine.ipset_catalog).


def _sinkhole_ip(ips: list[str]) -> list[str]:
    """Return the IPs from *ips* that fall into sinkhole/bogon networks."""
    from blockchecks.engine.ipset_catalog import ip_in_nets, sinkhole_nets

    nets = sinkhole_nets()
    return [raw.strip() for raw in ips or [] if ip_in_nets(raw, nets)]


def _cdn_family(ip: str) -> str | None:
    from blockchecks.engine.ipset_catalog import cdn_family

    return cdn_family(ip)


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
    for server, name in UDP_DNS_SERVERS:
        ips, err, lat = udp_resolve(domain, server, timeout=timeout)
        result.udp_server = server
        result.udp_name = name
        if ips and not err:
            result.udp_ips = ips
            result.udp_latency_ms = lat
            break
        if err:
            result.udp_error = err

    doh = doh_url or pick_working_doh(timeout=timeout)
    if not doh or not doh_is_trusted(doh):
        doh = pick_working_doh(timeout=timeout)
    result.doh_server = doh or ""
    ips, err, lat = doh_query(domain, doh, timeout=timeout) if doh else ([], "no working DoH", 0.0)
    result.doh_ips = ips
    result.doh_latency_ms = lat
    if err:
        result.doh_error = err
    result.untrusted_doh = {
        name: doh_query(domain, url, timeout=min(timeout, 2.0))[0]
        for url, name in untrusted_doh_servers()
    }

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
    return [audit_domain(d, doh_url=doh or None, timeout=timeout) for d in domains]


_VERDICT_STYLE = {
    "ok": (GREEN, "OK"),
    "no_resolution": (GREY, "NO A"),
    "tampered": (RED, "HIJACK"),
    "sinkhole": (RED, "SINKHOLE"),
    "doh_blocked": (YELLOW, "DoH DOWN"),
    "udp_blocked": (YELLOW, "UDP DOWN"),
}


def doh_display_name(url: str) -> str:
    """Human name for a catalog DoH URL, else the hostname."""
    target = (url or "").rstrip("/")
    named = {u.rstrip("/"): n for u, n in DOH_SERVERS}
    if name := named.get(target):
        return name
    return (urlsplit(url).hostname or url or "DoH") if url else "DoH"


def _ip_cell(ips: list[str], err: str | None = None) -> str:
    if ips:
        return ", ".join(ips[:3])
    if err:
        return err.replace("\n", " ").strip()[:48]
    return "—"


def _ms(latency: float) -> str:
    return f"{GREY}{latency:.0f}ms{RESET}" if latency else ""


def _verdict_tag(result: DnsAuditResult) -> str:
    color, label = _VERDICT_STYLE.get(
        result.verdict,
        (RED, "HIJACK") if result.tampering_detected else (GREY, result.verdict.upper() or "?"),
    )
    return f"{color}{label}{RESET}"


def _legend_lines(results: list[DnsAuditResult]) -> list[str]:
    sample = results[0]
    udp_who = sample.udp_name or "public"
    udp_ip = sample.udp_server or "?"
    doh_who = doh_display_name(sample.doh_server)
    doh_host = urlsplit(sample.doh_server).hostname or sample.doh_server or "?"
    untrusted = [name for _url, name in untrusted_doh_servers()]
    return [
        "",
        f"  {CYAN}DNS audit{RESET}  plaintext UDP:53  vs  encrypted DoH  (no DoT in this stack)",
        f"    UDP:53  {udp_who} ({udp_ip})     plaintext public resolver",
        f"    DoH     {doh_who} ({doh_host})   trusted — pin/verdict",
        *(
            [f"    DoH     {', '.join(untrusted)}     untrusted — display only, ignored"]
            if untrusted
            else []
        ),
        f"  {'─' * 72}",
    ]


def _audit_row_lines(result: DnsAuditResult) -> list[str]:
    udp_who = (
        f"{result.udp_name} ({result.udp_server})"
        if result.udp_server
        else (result.udp_name or "UDP:53")
    )
    doh_who = doh_display_name(result.doh_server)
    untrusted = [
        f"    DoH     {name:<22} {_ip_cell(ips)}   {GREY}untrusted{RESET}"
        for name, ips in result.untrusted_doh.items()
        if ips
    ]
    udp_ms = f"  {_ms(result.udp_latency_ms)}" if result.udp_latency_ms else ""
    doh_ms = f"  {_ms(result.doh_latency_ms)}" if result.doh_latency_ms else ""
    return [
        f"  {_verdict_tag(result)}  {result.domain}",
        f"    UDP:53  {udp_who:<22} {_ip_cell(result.udp_ips, result.udp_error)}{udp_ms}",
        f"    DoH     {doh_who:<22} {_ip_cell(result.doh_ips, result.doh_error)}{doh_ms}",
        *untrusted,
    ]


def _footer_lines(results: list[DnsAuditResult]) -> list[str]:
    tampered = [r for r in results if r.tampering_detected]
    unanswered = sorted(
        {name for r in results for name, ips in r.untrusted_doh.items() if not ips}
    )
    answered = any(ips for r in results for ips in r.untrusted_doh.values())
    note = (
        [f"  {GREY}{', '.join(unanswered)} DoH: no answers (untrusted, ignored){RESET}"]
        if unanswered and not answered
        else []
    )
    hijack = [f"    {r.domain}: {r.description}" for r in tampered]
    return [
        f"  {'─' * 72}",
        f"  Hijack: {len(tampered)}/{len(results)}",
        *hijack,
        *note,
    ]


def format_audit_table(results: list[DnsAuditResult]) -> str:
    """Render the UDP:53 vs DoH audit as a labeled multi-line report."""
    if not results:
        return ""
    lines = [
        *_legend_lines(results),
        *(line for r in results for line in _audit_row_lines(r)),
        *_footer_lines(results),
    ]
    return "\n".join(lines)


def print_audit_table(results: list[DnsAuditResult]) -> None:
    """Print plaintext UDP:53 vs trusted DoH, with resolver names."""
    if not results:
        return
    for line in format_audit_table(results).splitlines():
        log.info("%s", line)


def has_dns_hijack(results: list[DnsAuditResult]) -> bool:
    return any(r.tampering_detected for r in results)


def has_dns_sinkhole(results: list[DnsAuditResult]) -> bool:
    return any(r.verdict == "sinkhole" for r in results)


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
        if url and not self.doh_server:
            self.doh_server = url
        if not url:
            return self._pinned_first(domain, [])
        ips, err, _ = doh_query(domain, url, timeout=timeout)
        if ips and not err:
            self.set(domain, ips)
            return self._pinned_first(domain, ips)
        # Rotate DoH server on failure (skip the one that just failed)
        for alt, _name in trusted_doh_servers():
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
            log.info("%s", f"  live DoH failed for {domain}; using data_block IPs")
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
        except Exception as exc:
            log.warning("%s", f"  WARNING: DNS candidates failed for {domain} ({exc})")
            return []

    def prime(self, domains: list[str], doh_url: str | None = None) -> None:
        """Pre-resolve all domains for a batch run."""
        url = doh_url or pick_working_doh()
        if url:
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
    except Exception as exc:
        log.warning("%s", f"  WARNING: data_block DNS lookup failed for {domain} ({exc})")
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
    cache = DnsRunCache(doh_server=url or "")
    results: list[DnsAuditResult] = []
    if not skip_audit:
        results = audit_domains(domains, doh_url=url, timeout=timeout)
        print_audit_table(results)
        # UDP≠DoH is diagnostic: probes already use DoH + auto-pin (CURLOPT_RESOLVE).
        # Abort only on sinkhole/bogon — that would pin a reserved IP.
        if has_dns_sinkhole(results) and not allow_hijack:
            log.error(
                "\n  ERROR: DNS sinkhole/bogon answer. Use --allow-dns-hijack to "
                "continue or --no-secure-dns to disable DoH pre-resolve."
            )
            return cache, results, 1
        if has_dns_hijack(results):
            log.warning(
                "\n  WARNING: UDP:53 ≠ DoH for %d domain(s). "
                "Probes use DoH IPs + auto-pin; plaintext hijack is ignored.",
                sum(1 for r in results if r.tampering_detected),
            )

    cache.prime(domains, doh_url=url)
    return cache, results, 0
