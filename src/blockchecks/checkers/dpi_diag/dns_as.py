"""AS/org prefix checks and CGNAT sinkhole — dpi_diag only, not dns_secure."""

from __future__ import annotations

import ipaddress

# Expected unicast prefixes (not GeoLite). Discord Fastly/CF 8.6/8.47 included.
_EXPECT_PREFIX: dict[str, tuple[str, ...]] = {
    "discord.com": ("162.159.", "162.158.", "104.", "172.64.", "172.65.", "8.6.112.", "8.47.69."),
    "discord.gg": ("162.159.", "162.158.", "104."),
    "youtube.com": ("142.250.", "142.251.", "74.125.", "173.194.", "216.58."),
    "googlevideo.com": ("142.250.", "142.251.", "74.125.", "173.194."),
    "google.com": ("142.250.", "142.251.", "74.125.", "173.194.", "216.58."),
}

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _ips_of(row: dict) -> list[str]:
    raw = row.get("doh_ips") or row.get("udp_ips") or ""
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    return [p.strip() for p in str(raw).split(",") if p.strip()]


def as_org_mismatches(rows: list[dict]) -> list[str]:
    """Domains whose DoH/UDP A-records miss the expected CDN/org prefixes."""
    return [
        domain
        for row in rows
        if (domain := str(row.get("domain") or ""))
        and (prefixes := _EXPECT_PREFIX.get(domain))
        and (ips := _ips_of(row))
        and not any(ip.startswith(prefixes) for ip in ips)
    ]


def cgnat_ips(rows: list[dict]) -> list[str]:
    """IPs in RFC 6598 shared-address space (ISP stub / CGNAT)."""
    return list(dict.fromkeys(ip for row in rows for raw in _ips_of(row) if (ip := _cgnat_one(raw))))


def _cgnat_one(raw: str) -> str:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return ""
    return str(ip) if ip in _CGNAT else ""
