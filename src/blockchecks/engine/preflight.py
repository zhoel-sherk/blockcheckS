"""Startup preflight — blockcheck2 parity (BC2-2, BC2-3, BC2-5, BC2-11)."""

from __future__ import annotations

import asyncio
import subprocess
from dataclasses import dataclass, field

from blockchecks.checkers.dns_secure import DnsRunCache, doh_query, pick_working_doh
from blockchecks.checkers.ip_block import (
    IpBlockReport,
    print_ip_block_report,
    run_ip_block_cross_test,
)
from blockchecks.checkers.port_block import (
    PortBlockReport,
    print_port_block_report,
    run_port_block_probe,
)
from blockchecks.checkers.tcp_tls import check_tls
from blockchecks.engine.config import NFQWS2_BIN, UNBLOCKED_DOM


@dataclass
class PreflightOptions:
    unblocked_dom: str = UNBLOCKED_DOM
    timeout: float = 5.0
    skip_baseline: bool = False
    skip_port_block: bool = False
    skip_prolog: bool = False
    skip_ip_block: bool = False
    skip_nfqws2_check: bool = False
    abort_on_nfqws2: bool = False
    skip_dns_audit: bool = False
    force: bool = False
    verify_content: bool = False
    dns_cache: DnsRunCache | None = None
    store: object = None

    @classmethod
    def from_args(cls, args, *, dns_cache: DnsRunCache | None = None,
                  store: object = None) -> PreflightOptions:
        """Build options from CLI namespace (pair/main shared)."""
        return cls(
            unblocked_dom=getattr(args, "unblocked_dom", None) or UNBLOCKED_DOM,
            timeout=min(getattr(args, "timeout", 5.0), 8.0),
            skip_baseline=getattr(args, "skip_baseline", False),
            skip_port_block=getattr(args, "skip_port_block", False),
            skip_prolog=getattr(args, "skip_prolog", False),
            skip_ip_block=getattr(args, "skip_ip_block", False),
            skip_nfqws2_check=getattr(args, "skip_nfqws2_check", False),
            abort_on_nfqws2=getattr(args, "abort_on_nfqws2", False),
            skip_dns_audit=getattr(args, "skip_dns_audit", False),
            force=getattr(args, "force", False),
            verify_content=getattr(args, "prolog_content", False),
            dns_cache=dns_cache,
            store=store,
        )


@dataclass
class PreflightReport:
    nfqws2_pids: list[int] = field(default_factory=list)
    baseline_ok: bool = True
    baseline_domain: str = ""
    prolog_ok: dict[str, bool] = field(default_factory=dict)
    skip_domains: set[str] = field(default_factory=set)
    port_reports: list[PortBlockReport] = field(default_factory=list)
    ip_reports: list[IpBlockReport] = field(default_factory=list)
    exit_code: int = 0
    error: str = ""


def find_host_nfqws2_pids() -> list[int]:
    """Return PIDs of nfqws2 running on host (BC2-11)."""
    try:
        r = subprocess.run(
            ["pgrep", "-f", "nfqws2"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if r.returncode != 0:
            return []
        return [int(x) for x in r.stdout.split() if x.strip().isdigit()]
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        return []


def run_unblocked_baseline(
    unblocked_dom: str | None = None,
    timeout: float = 5.0,
    dns_cache: DnsRunCache | None = None,
) -> tuple[bool, str]:
    """Verify reference domain is reachable (BC2-2)."""
    dom = unblocked_dom or UNBLOCKED_DOM
    resolved_ip = None
    if dns_cache:
        resolved_ip = dns_cache.primary_ip(dom)
    r = check_tls(dom, timeout=timeout, pre_resolved_ip=resolved_ip, verify_content=False)
    if r.success:
        return True, dom
    return False, f"{dom} baseline failed: HTTP {r.http_status} {r.error or ''}".strip()


def run_prolog(
    domain: str,
    timeout: float = 5.0,
    dns_cache: DnsRunCache | None = None,
    *,
    verify_content: bool = False,
) -> bool:
    """Curl domain without nfqws2 — works without DPI bypass? (BC2-5)."""
    resolved_ip = dns_cache.primary_ip(domain) if dns_cache else None
    r = check_tls(
        domain,
        timeout=timeout,
        pre_resolved_ip=resolved_ip,
        verify_content=verify_content,
    )
    return r.success


def run_preflight(
    domains: list[str],
    opts: PreflightOptions | None = None,
) -> PreflightReport:
    """Run startup preflight chain (sync wrapper for non-async callers).

    Prefer ``await run_preflight_async()`` in async contexts.
    """
    import asyncio
    return asyncio.run(run_preflight_async(domains, opts))


async def _audit_domains_parallel(
    domains: list[str],
    cache: Any,
    timeout: float,
    store: Any = None,
) -> list[dict]:
    """Resolve all domains via UDP+DoH in parallel; return tampered entries."""
    from blockchecks.checkers.dns_secure import audit_domain

    doh = await asyncio.to_thread(pick_working_doh, timeout=timeout)

    async def _one(domain: str) -> dict:
        # audit_domain is sync I/O — run off the event loop
        result = await asyncio.to_thread(audit_domain, domain, doh, timeout)
        return {
            "domain": domain,
            "tampered": result.tampering_detected,
            "udp_ips": ", ".join(result.udp_ips) if result.udp_ips else "",
            "doh_ips": ", ".join(result.doh_ips) if result.doh_ips else "",
            "verdict": result.verdict,
            "doh_server": result.doh_server or "",
        }

    results = await asyncio.gather(*(_one(d) for d in domains))
    tampered = [r for r in results if r["tampered"]]

    if store and tampered:
        for r in tampered:
            await store.write_dns_audit_log(
                r["domain"], r["udp_ips"], r["doh_ips"],
                r["verdict"], r["doh_server"],
            )
        # Overwrite cache entries with real DoH IPs
        for r in tampered:
            ips = [ip.strip() for ip in r["doh_ips"].split(",") if ip.strip()]
            if ips and cache:
                cache.set(r["domain"], ips)

        print(f"\n  [DNS TAMPERED] {len(tampered)}/{len(domains)} domains:")
        for r in tampered:
            print(f"    {r['domain']}: UDP={r['udp_ips'] or '-'}  →  DoH={r['doh_ips']}")

    return tampered


async def run_preflight_async(
    domains: list[str],
    opts: PreflightOptions | None = None,
) -> PreflightReport:
    """Run startup preflight chain including parallel DNS audit."""
    o = opts or PreflightOptions()
    report = PreflightReport(baseline_domain=o.unblocked_dom or UNBLOCKED_DOM)
    cache = o.dns_cache

    if not o.skip_nfqws2_check:
        report.nfqws2_pids = find_host_nfqws2_pids()
        if report.nfqws2_pids:
            msg = (
                f"WARNING: nfqws2 already running on host (PIDs: "
                f"{', '.join(map(str, report.nfqws2_pids[:5]))}). "
                f"Tests may be invalid. Stop {NFQWS2_BIN} or use netns isolation."
            )
            print(f"\n  {msg}")
            if o.abort_on_nfqws2:
                report.exit_code = 1
                report.error = msg
                return report

    if not o.skip_baseline:
        ok, detail = run_unblocked_baseline(o.unblocked_dom, o.timeout, cache)
        report.baseline_ok = ok
        print(f"\n  Unblocked baseline ({report.baseline_domain}): {'OK' if ok else 'FAIL'}")
        if not ok:
            print(f"  {detail}")
            report.exit_code = 1
            report.error = detail
            return report

    # ── One-time parallel DNS audit (UDP vs DoH) ──
    if not o.skip_dns_audit and cache and o.store:
        await _audit_domains_parallel(domains, cache, o.timeout, store=o.store)

    ref = (o.unblocked_dom or UNBLOCKED_DOM).rstrip(".")
    for domain in domains:
        ips: list[str] = []
        if cache:
            ips = cache.resolve(domain, timeout=o.timeout)
        else:
            url = pick_working_doh(timeout=o.timeout)
            ips, _, _ = doh_query(domain, url, o.timeout)

        if not o.skip_port_block and ips:
            pr = run_port_block_probe(domain, ips, port=443, timeout=min(o.timeout, 3.0))
            report.port_reports.append(pr)
            print_port_block_report(pr)

        if not o.skip_prolog:
            works = run_prolog(
                domain,
                timeout=o.timeout,
                dns_cache=cache,
                verify_content=o.verify_content,
            )
            report.prolog_ok[domain] = works
            tag = "AVAILABLE (no bypass needed)" if works else "blocked or unreachable"
            print(f"\n  Prolog {domain}: {tag}")
            if works and not o.force:
                report.skip_domains.add(domain)
                print(f"  → skipping strategy tests for {domain} (use --force to override)")

        if not o.skip_ip_block and domain.rstrip(".") != ref:
            ip_r = run_ip_block_cross_test(
                domain,
                unblocked_domain=o.unblocked_dom,
                timeout=o.timeout,
                dns_cache=cache,
            )
            report.ip_reports.append(ip_r)
            print_ip_block_report(ip_r)

    return report
