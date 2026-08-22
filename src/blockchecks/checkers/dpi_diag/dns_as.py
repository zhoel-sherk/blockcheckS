"""AS/org prefix checks and CGNAT sinkhole — dpi_diag only, not dns_secure."""

from __future__ import annotations

from blockchecks.engine.ipset_catalog import cgnat_nets, expect_families, ip_in_nets


def _ips_of(row: dict) -> list[str]:
    raw = row.get("doh_ips") or row.get("udp_ips") or ""
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    return [p.strip() for p in str(raw).split(",") if p.strip()]


def as_org_mismatches(rows: list[dict]) -> list[str]:
    """Domains whose DoH/UDP A-records miss the expected CDN/org prefixes."""
    expect = expect_families()
    return [
        domain
        for row in rows
        if (domain := str(row.get("domain") or "").lower())
        and (nets := expect.get(domain))
        and (ips := _ips_of(row))
        and not any(ip_in_nets(ip, nets) for ip in ips)
    ]


def cgnat_ips(rows: list[dict]) -> list[str]:
    """IPs in RFC 6598 shared-address space (ISP stub / CGNAT)."""
    nets = cgnat_nets()
    return list(dict.fromkeys(raw for row in rows for raw in _ips_of(row) if ip_in_nets(raw, nets)))
