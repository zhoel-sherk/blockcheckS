"""Startup probes that fill TriageProfile before the strategy scan:
DNS, baseline reachability, fooling grid, L3/L4, stall, QUIC drop, UDP voice burst.
"""

from __future__ import annotations

import asyncio
import os
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
from blockchecks.checkers.tcp_tls import TlsResult, check_tls
from blockchecks.engine.config import NFQWS2_BIN, UNBLOCKED_DOM
from blockchecks.engine.fail_phase import FailPhase, classify_fail_phase
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
    skip_diagnostics: bool = True  # default off; from_args enables it on campaigns
    force: bool = False
    verify_content: bool = False
    dns_cache: DnsRunCache | None = None
    store: object = None
    fooling_probe_fn: object = None  # optional (strategy) → (ok, error, http)

    @classmethod
    def from_args(
        cls, args, *, dns_cache: DnsRunCache | None = None, store: object = None
    ) -> PreflightOptions:
        """Build options from CLI namespace (pair/main shared)."""
        no_preflight = bool(getattr(args, "no_preflight", False))
        quick = bool(getattr(args, "quick", False))
        return cls(
            unblocked_dom=getattr(args, "unblocked_dom", None) or UNBLOCKED_DOM,
            timeout=min(getattr(args, "timeout", 5.0), 8.0),
            skip_baseline=no_preflight or quick or getattr(args, "skip_baseline", False),
            skip_port_block=no_preflight or quick or getattr(args, "skip_port_block", False),
            skip_prolog=no_preflight or getattr(args, "skip_prolog", False),
            skip_ip_block=no_preflight or quick or getattr(args, "skip_ip_block", False),
            skip_nfqws2_check=no_preflight or getattr(args, "skip_nfqws2_check", False),
            abort_on_nfqws2=getattr(args, "abort_on_nfqws2", False),
            skip_dns_audit=no_preflight or getattr(args, "skip_dns_audit", False),
            skip_diagnostics=no_preflight or quick,
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
    """Return PIDs of nfqws2 running on the host."""
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
    """Verify the reference domain is reachable.

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
        r = check_tls(dom, timeout=timeout, pre_resolved_ip=resolved_ip, verify_content=False)
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


def run_prolog_tls(
    domain: str,
    timeout: float = 5.0,
    dns_cache: DnsRunCache | None = None,
    *,
    verify_content: bool = False,
) -> TlsResult:
    """Curl domain without nfqws2 — raw TLS result for fail-phase classification."""
    resolved_ip = dns_cache.primary_ip(domain) if dns_cache else None
    return check_tls(
        domain,
        timeout=timeout,
        pre_resolved_ip=resolved_ip,
        verify_content=verify_content,
    )


def run_prolog(
    domain: str,
    timeout: float = 5.0,
    dns_cache: DnsRunCache | None = None,
    *,
    verify_content: bool = False,
) -> bool:
    """Curl the domain without nfqws2: does it work without a bypass?"""
    return run_prolog_tls(
        domain, timeout=timeout, dns_cache=dns_cache, verify_content=verify_content
    ).success


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

    writer = getattr(store, "write_dns_audit_log", None) if store else None
    if callable(writer) and tampered:
        for r in tampered:
            await writer(
                r["domain"],
                r["udp_ips"],
                r["doh_ips"],
                r["verdict"],
                r["doh_server"],
            )
    if tampered:
        for r in tampered:
            ips = [ip.strip() for ip in r["doh_ips"].split(",") if ip.strip()]
            if ips and cache:
                cache.set(r["domain"], ips)
        print(f"\n  [DNS TAMPERED] {len(tampered)}/{len(domains)} domains:")
        for r in tampered:
            print(f"    {r['domain']}: UDP={r['udp_ips'] or '-'}  →  DoH={r['doh_ips']}")

    return list(results)


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

    # Parallel UDP vs DoH DNS check
    dns_rows: list[dict] = []
    if not o.skip_dns_audit and cache:
        dns_rows = await _audit_domains_parallel(domains, cache, o.timeout, store=o.store)

    # UDP voice burst >16KB
    # Simulate a voice stream to a Discord voice endpoint; a sustained >16KB
    # burst tells us whether the TSPU "voice" heuristic applies (endpoint
    # answers) or the transfer is dropped (blocked). Feeds strategy selection.
    report.udp_16kb_blocked, report.udp_16kb_detail = check_udp_16kb(o.timeout)
    if report.udp_16kb_detail:
        print(f"  UDP 16KB voice check: {report.udp_16kb_detail}")

    triage = _load_prior_triage()
    _apply_dns_audit(triage, dns_rows)
    triage.udp_blocked = bool(report.udp_16kb_blocked)
    triage.voice_ok = not report.udp_16kb_blocked
    report.triage = triage

    primary = domains[0] if domains else ""
    ref = report.baseline_domain or (o.unblocked_dom or UNBLOCKED_DOM).rstrip(".")
    for domain in domains:
        is_primary = domain == primary
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
            tls = run_prolog_tls(
                domain,
                timeout=o.timeout,
                dns_cache=cache,
                verify_content=o.verify_content,
            )
            works = tls.success
            report.prolog_ok[domain] = works
            tag = "AVAILABLE (no bypass needed)" if works else "blocked or unreachable"
            print(f"\n  Prolog {domain}: {tag}")
            _apply_prolog(triage, domain, tls, is_primary=is_primary)
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
            _apply_ip_block(triage, domain, ip_r, is_primary=is_primary)

        # L3/L4, stream stall, per-domain phase
        if domain not in report.skip_domains:
            _triage_domain(triage, domain, ips, o, cache, is_primary=is_primary)

    if not o.skip_diagnostics:
        diag_domain = next((d for d in domains if d not in report.skip_domains), primary)
        await _run_diagnostics(triage, diag_domain, cache, o)

    report.triage = triage
    await _persist_triage(triage, primary, o)
    return report


def _apply_dns_audit(triage: TriageProfile, rows: list[dict]) -> None:
    """Translate UDP/DoH audit rows into triage DNS flags."""
    if not rows:
        return
    triage.dns_hijacked = any(r.get("tampered") for r in rows)
    triage.dns_sinkhole = any(r.get("verdict") == "sinkhole" for r in rows)
    phase_for = {
        "sinkhole": FailPhase.DNS_SINKHOLE.value,
        "tampered": FailPhase.DNS_TAMPERED.value,
    }
    for r in rows:
        if not r.get("tampered") and r.get("verdict") not in phase_for:
            continue
        triage.domain_phases[r["domain"]] = phase_for.get(
            r.get("verdict", ""), FailPhase.DNS_TAMPERED.value
        )


def _apply_prolog(triage: TriageProfile, domain: str, tls: TlsResult, *, is_primary: bool) -> None:
    if tls.success:
        triage.domain_phases[domain] = FailPhase.PASS.value
        if is_primary:
            triage.handshake_phase = FailPhase.PASS
        return
    phase = classify_fail_phase(tls.error or "", tls.http_status)
    triage.domain_phases[domain] = phase.value
    if not is_primary:
        return
    triage.handshake_phase = phase
    triage.rst_at_sni = phase == FailPhase.TLS_RST_AT_SNI
    triage.silent_drop_after_sni = phase in (
        FailPhase.TLS_SILENT_DROP_AFTER_SNI,
        FailPhase.CONNECT_TIMEOUT,
    )


def _apply_ip_block(
    triage: TriageProfile, domain: str, ip_r: IpBlockReport, *, is_primary: bool
) -> None:
    blocked_ips = ip_r.blocked_ips
    ip_block_on = ip_r.ip_block_on
    if not isinstance(blocked_ips, list) or not isinstance(ip_block_on, list):
        return
    probed = blocked_ips[:5]
    if not probed or not ip_block_on or len(ip_block_on) < len(probed):
        return
    triage.domain_phases[domain] = FailPhase.IP_BLOCKED.value
    if is_primary:
        triage.unbypassable_l3 = True
        triage.l3_phase = FailPhase.IP_BLOCKED


async def _run_diagnostics(
    triage: TriageProfile,
    domain: str,
    cache: Any,
    opts: PreflightOptions,
) -> None:
    """Fooling grid / hop / ECH / HTTP:80 — best-effort, never aborts preflight."""
    ip = cache.primary_ip(domain) if cache else None
    try:
        from blockchecks.checkers.ttl_probe import probe_ttl

        if ip:
            hops = probe_ttl(ip, 443, timeout=min(opts.timeout, 2.0))
            triage.server_hops = hops.server_hops
            triage.dpi_hops = hops.dpi_hops
            triage.autottl_delta = hops.autottl_delta
            if hops.server_hops is not None:
                print(f"  Triage {domain}: hops server={hops.server_hops} dpi={hops.dpi_hops}")
    except Exception as e:  # noqa: BLE001
        print(f"  Triage {domain}: TTL probe skipped ({e})")

    probe_fn = opts.fooling_probe_fn
    runner = None
    if not callable(probe_fn):
        probe_fn, runner = await _try_live_strategy_probe(domain, opts, cache)
    try:
        if callable(probe_fn):
            await _run_fooling_and_blob_grids(triage, domain, probe_fn)
        elif triage.silent_drop_after_sni and not triage.split_mode:
            triage.split_mode = "first_byte"
        elif triage.rst_at_sni and not triage.split_mode:
            triage.split_mode = "sni_marker"
    except Exception as e:  # noqa: BLE001
        print(f"  Triage {domain}: fooling grid skipped ({e})")
    finally:
        if runner is not None:
            try:
                await runner.stop()
            except Exception:
                pass

    try:
        from blockchecks.checkers.fooling_probe import probe_ech_blocked, probe_http_blocked

        ech = probe_ech_blocked(domain, timeout=min(opts.timeout, 5.0), resolved_ip=ip)
        if ech is not None:
            triage.ech_blocked = ech
        triage.http_blocked = probe_http_blocked(
            domain, timeout=min(opts.timeout, 3.0), resolved_ip=ip
        )
    except Exception as e:  # noqa: BLE001
        print(f"  Triage {domain}: ECH/HTTP probe skipped ({e})")


async def _run_fooling_and_blob_grids(triage: TriageProfile, domain: str, probe_fn) -> None:
    from blockchecks.checkers.fooling_probe import (
        run_blob_grid_async,
        run_fooling_grid_async,
        run_split_grid_async,
    )

    grid = await run_fooling_grid_async(probe_fn)
    triage.viable_foolings = list(grid.viable)
    if grid.viable:
        print(f"  Triage {domain}: viable foolings {', '.join(grid.viable)}")
    triage.split_mode = (await run_split_grid_async(probe_fn)) or triage.split_mode
    blobs = await run_blob_grid_async(probe_fn)
    if blobs:
        triage.viable_blobs = blobs
        print(f"  Triage {domain}: viable blobs {', '.join(blobs)}")


async def _try_live_strategy_probe(domain: str, opts: PreflightOptions, cache: Any):
    """One-shot netns runner for fooling/split/blob grids. ``(probe_fn, runner)``."""
    try:
        from blockchecks.engine.async_runner import AsyncTestRunner
        from blockchecks.engine.generators.base import StrategyItem

        runner = AsyncTestRunner(
            pool_size=2,
            db=None,
            dns_cache=cache,
            auto_pin=False,
            netns_base=f"bs-pf-{os.getpid() % 10000:04d}",
        )
        await runner.start()

        async def probe(strategy: str) -> tuple[bool, str, int]:
            item = StrategyItem(label="preflight_diag", strategy=strategy)
            r = await runner.test_tcp(item, domain, timeout=min(opts.timeout, 5.0))
            return bool(r.success), r.error or "", int(r.http_code or 0)

        print(f"  Triage {domain}: live fooling grid (netns)")
        return probe, runner
    except Exception as e:  # noqa: BLE001 — no root / no nfqws2 / pool fail
        print(f"  Triage {domain}: live fooling grid skipped ({e})")
        return None, None


def _load_prior_triage() -> TriageProfile:
    try:
        from blockchecks.data_block.provider import get_provider_dir
        from blockchecks.data_block.store import ProviderStore

        prior = ProviderStore(get_provider_dir(allow_detect=False)).load_triage()
        return prior if prior is not None else TriageProfile()
    except Exception:
        return TriageProfile()


async def _persist_triage(triage: TriageProfile, primary: str, opts: PreflightOptions) -> None:
    try:
        from blockchecks.data_block.provider import get_provider_dir
        from blockchecks.data_block.store import ProviderStore

        ProviderStore(get_provider_dir(allow_detect=False)).save_triage(
            triage, primary_domain=primary
        )
    except Exception:
        pass
    saver = getattr(opts.store, "save_triage_snapshot", None)
    if not callable(saver):
        return
    try:
        result = saver(primary, triage.to_dict())
        if asyncio.iscoroutine(result):
            await result
    except Exception:
        pass


def _triage_domain(
    triage: TriageProfile,
    domain: str,
    ips: list[str],
    opts: PreflightOptions,
    cache: Any,
    *,
    is_primary: bool = True,
) -> None:
    """Run L3/L4 + stream-stall triage for one domain.

    Scalar fields on *triage* are written only for the primary domain so a
    multi-domain scan does not clobber the campaign profile with the last host.
    """
    from blockchecks.checkers.curl_probe import run_stream_triage_probe
    from blockchecks.checkers.l3_probe import probe_l3

    # L3/L4 blackhole check on the first resolved IP.
    if ips:
        r = probe_l3(ips[0], 443, timeout=min(opts.timeout, 3.0), use_raw=False)
        if r.phase in (FailPhase.L4_SYN_DROP, FailPhase.ICMP_BLOCK, FailPhase.L4_RST_AT_SYN):
            triage.domain_phases[domain] = r.phase.value
            if is_primary:
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
        phase = (
            FailPhase(res.phase) if res.phase in FailPhase._value2member_map_ else FailPhase.UNKNOWN
        )
        triage.domain_phases.setdefault(domain, phase.value)
        if is_primary:
            triage.stall_phase = phase
            triage.stall_at_bytes = res.stall_at_bytes
            triage.read_rate_bps = res.read_rate_bps
            triage.bandwidth_throttled = res.phase == "bandwidth_throttled"
            if phase == FailPhase.TLS_RST_AT_SNI:
                triage.rst_at_sni = True
            if phase == FailPhase.TLS_SILENT_DROP_AFTER_SNI:
                triage.silent_drop_after_sni = True
        if phase not in (FailPhase.PASS, FailPhase.UNKNOWN):
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
        if is_primary:
            triage.client_hello_len = fp.client_hello_len
            triage.is_tls_fingerprint_blocked = fp.is_fingerprint_blocked
            triage.requires_postquantum_awareness = fp.client_hello_len > 1400
            triage.fingerprint_pass = dict(fp.profile_pass)
        if fp.is_fingerprint_blocked:
            print(f"  Triage {domain}: TLS fingerprint-blocked (chrome fails, lighter passes)")
        elif is_primary and triage.requires_postquantum_awareness:
            print(f"  Triage {domain}: post-quantum ClientHello ~{fp.client_hello_len}B")
    except Exception as e:  # noqa: BLE001
        print(f"  Triage {domain}: TLS profile probe skipped ({e})")

    # Raw QUIC Initial drop probe (host default netns, one-shot UDP :443).
    try:
        from blockchecks.checkers.quic_raw import probe_quic_initial

        qip = ips[0] if ips else cache.primary_ip(domain) if cache else None
        if qip:
            qr = probe_quic_initial(qip, 443, timeout=min(opts.timeout, 3.0))
            if is_primary:
                triage.quic_drop = qr.phase in (
                    FailPhase.QUIC_DROP,
                    FailPhase.UDP_BLOCKED,
                )
                if qr.phase == FailPhase.UDP_BLOCKED:
                    triage.udp_blocked = True
            print(f"  Triage {domain}: QUIC Initial {qr.phase.value} ({qr.blob_used})")
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
        elif "timeout" in detail and "unauthenticated" not in detail:
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
                return [(e["ip"], int(e.get("port", 50004))) for e in eps[:3] if e.get("ip")]
    except Exception:
        pass
    return [("35.217.42.214", 50004)]
