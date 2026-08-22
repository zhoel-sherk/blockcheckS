"""Tell SNI blocks from IP blocks by swapping domain and connect-IP:
baseline host on its own IP, blocked SNI to a clean IP, clean SNI to each blocked IP.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from blockchecks.checkers.dns_secure import DnsRunCache, pick_working_doh
from blockchecks.checkers.tcp_tls import TlsResult, check_tls
from blockchecks.engine.config import UNBLOCKED_DOM

log = logging.getLogger(__name__)


@dataclass
class IpBlockProbe:
    label: str
    sni_domain: str
    connect_ip: str
    result: TlsResult


@dataclass
class IpBlockReport:
    blocked_domain: str
    unblocked_domain: str
    baseline_ok: bool = False
    unblocked_ip: str = ""
    blocked_ips: list[str] = field(default_factory=list)
    probes: list[IpBlockProbe] = field(default_factory=list)
    sni_block_likely: bool = False
    ip_block_on: list[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""


def _probe(
    label: str,
    sni_domain: str,
    connect_ip: str,
    timeout: float,
) -> IpBlockProbe:
    r = check_tls(
        sni_domain,
        timeout=timeout,
        pre_resolved_ip=connect_ip,
        verify_content=False,
    )
    return IpBlockProbe(label=label, sni_domain=sni_domain, connect_ip=connect_ip, result=r)


def run_ip_block_cross_test(
    blocked_domain: str,
    unblocked_domain: str | None = None,
    timeout: float = 5.0,
    dns_cache: DnsRunCache | None = None,
) -> IpBlockReport:
    """Run IP-block cross-test for one blocked domain."""
    unblocked = unblocked_domain or UNBLOCKED_DOM
    report = IpBlockReport(blocked_domain=blocked_domain, unblocked_domain=unblocked)

    baseline = check_tls(unblocked, timeout=timeout, verify_content=False)
    report.baseline_ok = baseline.success
    if not baseline.success:
        report.skipped = True
        report.skip_reason = (
            f"{unblocked} baseline failed: {baseline.error or baseline.http_status}"
        )
        return report

    cache = dns_cache or DnsRunCache(doh_server=pick_working_doh(timeout=timeout))
    report.unblocked_ip = cache.primary_ip(unblocked) or ""
    report.blocked_ips = cache.resolve(blocked_domain, timeout=timeout)

    if not report.unblocked_ip:
        report.skipped = True
        report.skip_reason = f"{unblocked} does not resolve via DoH"
        return report

    report.probes.append(
        _probe(
            f"{blocked_domain} SNI @ {unblocked} IP",
            blocked_domain,
            report.unblocked_ip,
            timeout,
        )
    )
    if report.probes[-1].result.success:
        report.sni_block_likely = True

    for ip in report.blocked_ips[:5]:
        p = _probe(
            f"{unblocked} SNI @ {blocked_domain} IP {ip}",
            unblocked,
            ip,
            timeout,
        )
        report.probes.append(p)
        if not p.result.success:
            report.ip_block_on.append(ip)

    return report


def print_ip_block_report(report: IpBlockReport) -> None:
    """Human-readable summary."""
    log.info(
        "%s", f"\n  IP-block cross-test: {report.blocked_domain} (ref {report.unblocked_domain})"
    )
    if report.skipped:
        log.info("%s", f"  SKIP: {report.skip_reason}")
        return
    log.info("%s", f"  Baseline {report.unblocked_domain}: OK")
    log.info("%s", f"  Unblocked IP: {report.unblocked_ip}")
    log.info("%s", f"  Blocked IPs:  {', '.join(report.blocked_ips[:5]) or '—'}")
    for p in report.probes:
        tag = "OK" if p.result.success else "FAIL"
        st = p.result.http_status or p.result.error or "?"
        log.info("%s", f"    [{tag}] {p.label} → HTTP {st}")
    if report.sni_block_likely:
        log.info("  → SNI-based block likely (blocked host works on clean IP)")
    if report.ip_block_on:
        cdn_hint = _cdn_hint(report.ip_block_on)
        log.info("%s", f"  → IP block likely on: {', '.join(report.ip_block_on)}")
        if cdn_hint:
            log.info("%s", f"    ⚠  {cdn_hint}")


_CDN_OCTETS: tuple[str, ...] = (
    "104.",
    "162.158.",
    "162.159.",
    "172.64.",
    "172.65.",
    "172.66.",
    "172.67.",
    # Discord Fastly/CF anycast (AS13335), e.g. dl.discordapp.net
    "8.6.112.",
    "8.47.69.",
)
_CDN_NAMES: str = "Cloudflare"


def _cdn_hint(ips: list[str]) -> str:
    cdn_ips = [ip for ip in ips if ip.startswith(_CDN_OCTETS)]
    if not cdn_ips:
        return ""
    return (
        f"{len(cdn_ips)}/{len(ips)} IP(s) appear to be {_CDN_NAMES} CDN — "
        "SNI enforcement indistinguishable from IP block. "
        "Verify with origin-server IPs."
    )


def run_ip_block_preflight(
    domains: list[str],
    unblocked_domain: str | None = None,
    timeout: float = 5.0,
    dns_cache: DnsRunCache | None = None,
) -> list[IpBlockReport]:
    """Run cross-test for each domain (skip unblocked ref domain)."""
    ref = unblocked_domain or UNBLOCKED_DOM
    reports = []
    for domain in domains:
        if domain.rstrip(".") == ref.rstrip("."):
            continue
        reports.append(
            run_ip_block_cross_test(
                domain,
                unblocked_domain=ref,
                timeout=timeout,
                dns_cache=dns_cache,
            )
        )
    return reports
