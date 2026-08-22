"""Orchestrate dpi_diag probes and overlay onto TriageProfile."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from blockchecks.checkers.dpi_diag.classify import classify_stage
from blockchecks.checkers.dpi_diag.dns_as import as_org_mismatches, cgnat_ips
from blockchecks.checkers.dpi_diag.probes import (
    probe_cidr_whitelist,
    probe_fat_keepalive,
    probe_l4_25,
    probe_siberian,
    probe_sni_whitelist,
)

log = logging.getLogger(__name__)


@dataclass
class DpiDiagReport:
    sni_whitelist: list[str] = field(default_factory=list)
    fat: dict[str, Any] = field(default_factory=dict)
    l4_25: dict[str, Any] = field(default_factory=dict)
    siberian: bool | None = None
    cidr_whitelist: bool | None = None
    dns_as_mismatch: list[str] = field(default_factory=list)
    cgnat_sinkhole: list[str] = field(default_factory=list)
    classified: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def apply_overlay(triage: Any, report: DpiDiagReport) -> None:
    """Copy diag findings onto triage. Does not flip dns_sinkhole / unbypassable_l3."""
    if err := (report.fat or {}).get("error"):
        report.classified["fat"] = classify_stage(str(err))
    triage.dpi_diag = report.to_dict()
    if report.sni_whitelist:
        triage.viable_hosts = list(report.sni_whitelist)


async def run_dpi_diag(
    domains: list[str],
    triage: Any,
    cache: Any,
    opts: Any,
    *,
    dns_rows: list[dict] | None = None,
) -> DpiDiagReport:
    """Run borrowed probes. Network I/O in threads; never raises into preflight."""
    primary = domains[0] if domains else ""
    ip = cache.primary_ip(primary) if cache and primary else ""
    timeout = min(getattr(opts, "timeout", 5.0), 5.0)
    report = DpiDiagReport()
    rows = list(dns_rows or [])
    report.dns_as_mismatch = as_org_mismatches(rows)
    report.cgnat_sinkhole = cgnat_ips(rows)
    try:
        await _run_live(report, primary, ip, timeout)
    except Exception as exc:  # noqa: BLE001
        log.info("%s", f"  dpi-diag: live probes skipped ({exc})")
    apply_overlay(triage, report)
    _log_report(report)
    return report


async def _run_live(report: DpiDiagReport, host: str, ip: str, timeout: float) -> None:
    if ip:
        report.sni_whitelist = await asyncio.to_thread(
            probe_sni_whitelist, ip, timeout=timeout
        )
        report.fat = await asyncio.to_thread(probe_fat_keepalive, host, ip, timeout=timeout)
        report.siberian = await asyncio.to_thread(probe_siberian, host, ip, timeout=timeout)
        if host:
            report.l4_25 = await asyncio.to_thread(
                probe_l4_25, host, ip=ip, timeout=timeout
            )
    report.cidr_whitelist = await asyncio.to_thread(probe_cidr_whitelist, timeout=timeout)


def _log_report(report: DpiDiagReport) -> None:
    log.info(
        "%s",
        "  dpi-diag: "
        f"sni_wl={report.sni_whitelist or '-'} "
        f"fat={report.fat.get('ok')} "
        f"l4-25={report.l4_25.get('ok')} "
        f"siberian={report.siberian} "
        f"cidr_wl={report.cidr_whitelist} "
        f"as_mismatch={report.dns_as_mismatch or '-'} "
        f"cgnat={report.cgnat_sinkhole or '-'} "
        f"class={report.classified or '-'}",
    )
