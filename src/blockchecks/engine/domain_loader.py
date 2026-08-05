"""Domain list loading with denylist filter (Phase 11 A1)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from blockchecks.engine.config import PROJECT_DIR
from blockchecks.engine.preset_paths import RESERVED_DOMAIN_FILES, resolve_domain_preset

DOMAINS_PRESET_DIR = os.path.join(PROJECT_DIR, "presets", "domains")
DEFAULT_DOMAINS_FILE = os.path.join(DOMAINS_PRESET_DIR, "coverage-tcp.txt")
FULL_COVERAGE_FILE = os.path.join(DOMAINS_PRESET_DIR, "coverage.txt")
DENYLIST_FILE = os.path.join(DOMAINS_PRESET_DIR, "denylist.txt")


@dataclass(frozen=True)
class DenylistEntry:
    domain: str
    category: str


@dataclass
class DomainLoadResult:
    domains: list[str]
    source: str
    skipped: list[DenylistEntry]
    denylist_applied: bool


def preset_path(name: str) -> str:
    """Path to presets/domains/{name}.txt (path-jailed; see engine.preset_paths)."""
    return str(resolve_domain_preset(name))


def is_domain_preset_file(path: str) -> bool:
    return os.path.basename(path) not in RESERVED_DOMAIN_FILES


def read_domain_lines(path: str) -> list[str]:
    """Read FQDNs from a preset file (comments and blanks skipped)."""
    out: list[str] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            dom = line.split("#", 1)[0].strip()
            if dom:
                out.append(dom)
    return out


def load_denylist(path: str | None = None) -> list[DenylistEntry]:
    """Parse denylist.txt — domain + optional # category comment."""
    deny_path = path or DENYLIST_FILE
    if not os.path.exists(deny_path):
        return []
    entries: list[DenylistEntry] = []
    with open(deny_path, encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            if "#" in raw:
                dom_part, cat_part = raw.split("#", 1)
                domain = dom_part.strip().lower()
                category = cat_part.strip()
            else:
                domain = raw.lower()
                category = ""
            if domain:
                entries.append(DenylistEntry(domain=domain, category=category))
    return entries


def apply_denylist(
    domains: list[str],
    *,
    denylist: list[DenylistEntry] | None = None,
    allow_unsafe: bool = False,
) -> tuple[list[str], list[DenylistEntry]]:
    """Filter domains against denylist (exact FQDN match, case-insensitive)."""
    if allow_unsafe or not domains:
        return list(domains), []
    entries = denylist if denylist is not None else load_denylist()
    if not entries:
        return list(domains), []
    deny_map = {e.domain: e for e in entries}
    blocked = set(deny_map)
    kept: list[str] = []
    skipped: list[DenylistEntry] = []
    for dom in domains:
        key = dom.lower().split("/")[0]
        if key in blocked:
            skipped.append(deny_map.get(key, DenylistEntry(key, "")))
        else:
            kept.append(dom)
    return kept, skipped


def load_preset(
    name: str,
    *,
    allow_unsafe: bool = False,
) -> DomainLoadResult:
    """Load presets/domains/{name}.txt with denylist filter (path-jailed)."""
    path = preset_path(name)
    return load_domains(path, allow_unsafe=allow_unsafe)


def load_domains(
    path: str,
    *,
    allow_unsafe: bool = False,
    denylist_path: str | None = None,
) -> DomainLoadResult:
    """Load domains from file and apply denylist unless allow_unsafe."""
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    raw = read_domain_lines(path)
    denylist = load_denylist(denylist_path)
    domains, skipped = apply_denylist(raw, denylist=denylist, allow_unsafe=allow_unsafe)
    return DomainLoadResult(
        domains=domains,
        source=path,
        skipped=skipped,
        denylist_applied=not allow_unsafe and bool(skipped),
    )


def format_skip_summary(skipped: list[DenylistEntry], *, max_show: int = 8) -> str:
    if not skipped:
        return ""
    parts = []
    for entry in skipped[:max_show]:
        if entry.category:
            parts.append(f"{entry.domain} ({entry.category})")
        else:
            parts.append(entry.domain)
    extra = len(skipped) - max_show
    tail = f", +{extra} more" if extra > 0 else ""
    return f"skipped {len(skipped)}: {', '.join(parts)}{tail}"


async def warn_zero_pass_domains(
    db,
    domains: list[str],
    *,
    min_results: int = 10,
    protos: tuple[str, ...] = ("tcp", "http", "quic"),
) -> list[str]:
    """Return domains with min_results+ tests and 0% PASS (A1d)."""
    if min_results <= 0 or not domains:
        return []
    zero: list[str] = []
    for domain in domains:
        stats = await db.domain_pass_stats(domain, protos=protos)
        if stats["total"] >= min_results and stats["passed"] == 0:
            zero.append(domain)
    return zero
