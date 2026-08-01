"""Phase 11 B2 — multi-domain curl fan-out helpers and risk guards."""

from __future__ import annotations

from dataclasses import dataclass

from blockchecks.engine.config import GOOGLEVIDEO_RANGE_SIZE

# Domains needing per-request curl options incompatible with mixed fan-out batches.
_SPECIAL_DOMAIN_MARKERS = ("googlevideo",)


@dataclass(frozen=True)
class CurlProfile:
    """Per-domain curl options for a fan-out batch."""

    use_ech: bool
    headers_extra: str  # fragment inside headers dict, e.g. ', "Range": "bytes=0-1"'
    special: bool  # must run solo (googlevideo videoplayback curl profile)


def curl_profile(domain: str, *, protocol: str = "tls12", disable_ech: bool = False) -> CurlProfile:
    is_http = protocol == "http"
    dom = domain.lower().split("/")[0]
    is_gv = not is_http and any(m in dom for m in _SPECIAL_DOMAIN_MARKERS)
    use_ech = not is_http and not disable_ech and not is_gv
    headers_extra = ""
    if is_gv:
        range_end = GOOGLEVIDEO_RANGE_SIZE - 1
        headers_extra = f', "Range": "bytes=0-{range_end}"'
    return CurlProfile(use_ech=use_ech, headers_extra=headers_extra, special=is_gv)


def profiles_compatible(a: CurlProfile, b: CurlProfile) -> bool:
    return (a.use_ech, a.headers_extra, a.special) == (b.use_ech, b.headers_extra, b.special)


def fanout_batches(
    domains: list[str],
    *,
    protocol: str = "tls12",
    disable_ech: bool = False,
    curl_parallel: int = 1,
) -> list[list[str]]:
    """Partition domains into fan-out batches (special domains always solo)."""
    n = max(1, int(curl_parallel))
    if n == 1:
        return [[d] for d in domains]

    batches: list[list[str]] = []
    bucket: list[str] = []
    bucket_profile: CurlProfile | None = None

    def flush() -> None:
        nonlocal bucket, bucket_profile
        if not bucket:
            return
        for i in range(0, len(bucket), n):
            batches.append(bucket[i : i + n])
        bucket = []
        bucket_profile = None

    for domain in domains:
        prof = curl_profile(domain, protocol=protocol, disable_ech=disable_ech)
        if prof.special:
            flush()
            batches.append([domain])
            continue
        if bucket_profile is None:
            bucket_profile = prof
            bucket = [domain]
        elif profiles_compatible(bucket_profile, prof):
            bucket.append(domain)
        else:
            flush()
            bucket_profile = prof
            bucket = [domain]
    flush()
    return batches


def fanout_allowed(
    *,
    curl_parallel: int,
    use_family_gates: bool,
    domains: list[str],
    protocol: str = "tls12",
) -> tuple[bool, str]:
    """Return (ok, reason) for enabling B2 fan-out."""
    if curl_parallel <= 1:
        return False, "curl_parallel<=1"
    if use_family_gates:
        return False, "family_gates active (per-domain need_* chain)"
    special = [
        d
        for d in domains
        if curl_profile(d, protocol=protocol).special
    ]
    if special:
        return True, (
            f"special domains run solo: {', '.join(special[:3])}"
            + (f" +{len(special) - 3}" if len(special) > 3 else "")
        )
    return True, ""
