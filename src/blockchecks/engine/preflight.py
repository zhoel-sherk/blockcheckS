"""Startup preflight — blockcheck2 parity (BC2-2, BC2-3, BC2-5, BC2-11)."""

from __future__ import annotations

import asyncio
import subprocess
from dataclasses import dataclass, field
from typing import Any

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
from blockchecks.engine.fail_phase import FailPhase
from blockchecks.engine.triage import TriageProfile


async def _sync_dns_to_data_block(results: list[dict]) -> None:
    """Persist DoH results (all + tampered) into data_block dns.db.

    Best-effort: any failure (missing submodule, no provider, write error) is
    silently ignored.
    """
    try:
        from blockchecks.data_block.provider import get_provider_dir
        from blockchecks.data_block.store import ProviderStore

        store = ProviderStore(get_provider_dir())
        records: dict[str, list[str]] = {}
        tampered_rows: list[dict] = []
        for r in results:
            ips = [ip.strip() for ip in r.get("doh_ips", "").split(",") if ip.strip()]
            if ips:
                records[r["domain"]] = ips
            if r.get("tampered"):
                tampered_rows.append(
                    {
                        "domain": r["domain"],
                        "udp_ips": r.get("udp_ips", ""),
                        "doh_ips": r.get("doh_ips", ""),
                        "verdict": r.get("verdict", ""),
                    }
                )
        await store.save_dns_records(records)
        await store.save_dns_tampered(tampered_rows)
        store.write_hosts(records)
    except Exception:
        pass


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
    def from_args(
        cls, args, *, dns_cache: DnsRunCache | None = None, store: object = None
    ) -> PreflightOptions:
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
    udp_16kb_blocked: bool = False
    udp_16kb_detail: str = ""
    triage: TriageProfile | None = None
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


def _baseline_candidates(unblocked_dom: str | None) -> list[str]:
    """Ordered list of baseline domains to try (primary first)."""
    from blockchecks.engine.config import UNBLOCKED_DOMS

    primary = (unblocked_dom or UNBLOCKED_DOM).strip().rstrip(".")
    if not primary:
        return list(UNBLOCKED_DOMS)
    return [primary] + [d for d in UNBLOCKED_DOMS if d != primary]


def run_unblocked_baseline(
    unblocked_dom: str | None = None,
    timeout: float = 5.0,
    dns_cache: DnsRunCache | None = None,
) -> tuple[bool, str]:
    """Verify reference domain is reachable (BC2-2).

    Tries the primary UNBLOCKED_DOM first, then fallbacks from UNBLOCKED_DOMS.
    When live DNS is unavailable for a candidate, falls back to a cached IP
    from data_block dns.db.  Returns (ok, working_domain_or_error).
    """
    for dom in _baseline_candidates(unblocked_dom):
        resolved_ip = None
        if dns_cache:
            resolved_ip = dns_cache.primary_ip(dom)
        # No live resolution → use data_block cached IP (anti-hijack fallback)
        if not resolved_ip:
            resolved_ip = _data_block_cached_ip(dom)
        r = check_tls(
            dom, timeout=timeout, pre_resolved_ip=resolved_ip, verify_content=False
        )
        if r.success:
            return True, dom
    last = _baseline_candidates(unblocked_dom)[-1]
    r = check_tls(last, timeout=timeout, verify_content=False)
    return False, f"{last} baseline failed: HTTP {r.http_status} {r.error or ''}".strip()


def _data_block_cached_ip(domain: str) -> str | None:
    """Return first cached IP for *domain* from data_block dns.db (best-effort)."""
    try:
        from blockchecks.data_block.provider import get_provider_dir
        from blockchecks.data_block.store import ProviderStore

        store = ProviderStore(get_provider_dir(allow_detect=False))
        recs = store.load_dns_records_sync()
        value = recs.get(domain)
        if isinstance(value, tuple):
            return value[0][0] if value[0] else None
        if value:
            return value[0]
    except Exception:
        pass
    return None


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

    await _sync_dns_to_data_block(results)

    if store and tampered:
        for r in tampered:
            await store.write_dns_audit_log(
                r["domain"],
                r["udp_ips"],
                r["doh_ips"],
                r["verdict"],
                r["doh_server"],
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
        # Working baseline (may be a fallback host) → reuse for IP-block cross-tests
        if detail and detail in _baseline_candidates(o.unblocked_dom):
            report.baseline_domain = detail

    # ── One-time parallel DNS audit (UDP vs DoH) ──
    if not o.skip_dns_audit and cache and o.store:
        await _audit_domains_parallel(domains, cache, o.timeout, store=o.store)

    # ── UDP voice-traffic >16KB check (dpi-detector analogue) ──
    # Simulate a voice stream to a Discord voice endpoint; a sustained >16KB
    # burst tells us whether the TSPU "voice" heuristic applies (endpoint
    # answers) or the transfer is dropped (blocked). Feeds strategy selection.
    report.udp_16kb_blocked, report.udp_16kb_detail = check_udp_16kb(o.timeout)
    if report.udp_16kb_detail:
        print(f"  UDP 16KB voice check: {report.udp_16kb_detail}")

    triage = TriageProfile()
    triage.udp_blocked = bool(report.udp_16kb_blocked)
    report.triage = triage

    ref = report.baseline_domain or (o.unblocked_dom or UNBLOCKED_DOM).rstrip(".")
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
                unblocked_domain=ref,
                timeout=o.timeout,
                dns_cache=cache,
            )
            report.ip_reports.append(ip_r)
            print_ip_block_report(ip_r)

        # ── Triage: L3/L4 + stream stall + per-domain phase (first probe only) ──
        if report.triage is not None and not report.triage.unbypassable_l3:
            _triage_domain(triage, domain, ips, o, cache)

    return report


def _triage_domain(
    triage: TriageProfile,
    domain: str,
    ips: list[str],
    opts: PreflightOptions,
    cache: Any,
) -> None:
    """Run L3/L4 + stream-stall triage for one domain (first probe)."""
    from blockchecks.checkers.curl_probe import run_stream_triage_probe
    from blockchecks.checkers.l3_probe import probe_l3

    # L3/L4 blackhole check on the first resolved IP.
    if ips:
        r = probe_l3(ips[0], 443, timeout=min(opts.timeout, 3.0), use_raw=False)
        if r.phase in (FailPhase.L4_SYN_DROP, FailPhase.ICMP_BLOCK, FailPhase.L4_RST_AT_SYN):
            triage.unbypassable_l3 = True
            triage.l3_phase = r.phase
            print(f"  Triage {domain}: {r.phase.value} ({r.ip}:{r.port})")
            return

    # Stream stall probe (Range 0-256KB) — first domain only.
    try:
        resolved_ip = cache.primary_ip(domain) if cache else None
        res = run_stream_triage_probe(
            f"https://{domain}",
            timeout=min(opts.timeout, 8.0),
            resolved_ip=resolved_ip,
        )
        triage.stall_phase = FailPhase(res.phase) if res.phase in FailPhase.__members__ else FailPhase.UNKNOWN
        triage.stall_at_bytes = res.stall_at_bytes
        triage.read_rate_bps = res.read_rate_bps
        triage.bandwidth_throttled = res.phase == "bandwidth_throttled"
        if triage.stall_phase not in (FailPhase.PASS, FailPhase.UNKNOWN):
            print(f"  Triage {domain}: {res.phase} @ {res.stall_at_bytes or 0}B")
    except Exception as e:  # noqa: BLE001 — triage must never abort preflight
        print(f"  Triage {domain}: stream probe skipped ({e})")

    # Multi-profile TLS fingerprint (chrome vs firefox vs safari vs bare).
    try:
        from blockchecks.checkers.curl_probe import run_tls_profile_probe

        fp = run_tls_profile_probe(
            domain,
            timeout=min(opts.timeout, 5.0),
            resolved_ip=cache.primary_ip(domain) if cache else None,
        )
        triage.client_hello_len = fp.client_hello_len
        triage.is_tls_fingerprint_blocked = fp.is_fingerprint_blocked
        triage.requires_postquantum_awareness = fp.client_hello_len > 1400
        triage.fingerprint_pass = dict(fp.profile_pass)
        if fp.is_fingerprint_blocked:
            print(f"  Triage {domain}: TLS fingerprint-blocked (chrome fails, lighter passes)")
        elif triage.requires_postquantum_awareness:
            print(f"  Triage {domain}: post-quantum ClientHello ~{fp.client_hello_len}B")
    except Exception as e:  # noqa: BLE001
        print(f"  Triage {domain}: TLS profile probe skipped ({e})")

    # Raw QUIC Initial drop probe (host default netns, one-shot UDP :443).
    try:
        from blockchecks.checkers.quic_raw import probe_quic_initial

        qip = ips[0] if ips else cache.primary_ip(domain) if cache else None
        if qip:
            qr = probe_quic_initial(qip, 443, timeout=min(opts.timeout, 3.0))
            triage.quic_drop = qr.phase in (
                FailPhase.QUIC_DROP, FailPhase.UDP_BLOCKED,
            )
            triage.udp_blocked = qr.phase == FailPhase.UDP_BLOCKED
            print(
                f"  Triage {domain}: QUIC Initial {qr.phase.value}"
                f" ({qr.blob_used})"
            )
    except Exception as e:  # noqa: BLE001
        print(f"  Triage {domain}: QUIC probe skipped ({e})")


def check_udp_16kb(timeout: float = 5.0) -> tuple[bool, str]:
    """UDP voice-traffic >16KB check (dpi-detector analogue).

    Sends a >16KB UDP media burst to a discovered Discord voice endpoint.
    ``blocked=True`` means the burst was dropped (TSPU cut the voice stream);
    ``blocked=False`` means an endpoint answered (voice heuristic applies /
    transfer survives). Returns (blocked, detail).
    """
    from blockchecks.checkers.udp_voice import voice_burst_probe

    try:
        endpoints = _voice_endpoint_candidates()
    except Exception:
        endpoints = []
    if not endpoints:
        return False, "no voice endpoint candidates"

    ok_count = 0
    for ip, port in endpoints[:3]:
        ok, _ms, detail = voice_burst_probe(ip, port, timeout=min(timeout, 3.0))
        if ok:
            ok_count += 1
        elif "timeout" in detail:
            return True, f"burst dropped (blocked) at {ip}:{port}"
    if ok_count:
        return False, f"{ok_count}/{len(endpoints[:3])} endpoints answered burst (>16KB)"
    return True, "all endpoints dropped burst (>16KB) — voice stream likely blocked"


def _voice_endpoint_candidates() -> list[tuple[str, int]]:
    """Short list of voice endpoint IP:port candidates (cache → default)."""
    from blockchecks.engine.paths import VOICE_DNS_CACHE_FILE

    try:
        import json as _json

        if VOICE_DNS_CACHE_FILE.is_file():
            data = _json.loads(VOICE_DNS_CACHE_FILE.read_text(encoding="utf-8"))
            eps = data.get("endpoints", [])
            if eps:
                return [
                    (e["ip"], int(e.get("port", 50004)))
                    for e in eps[:3]
                    if e.get("ip")
                ]
    except Exception:
        pass
    return [("35.217.42.214", 50004)]
