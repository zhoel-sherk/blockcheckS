"""Load CIDR/IP catalogs from presets/ipset (user overlay, then bundled)."""

from __future__ import annotations

import ipaddress
import logging
import re
import shutil
from dataclasses import dataclass
from functools import lru_cache
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path

from blockchecks.engine.paths import USER_PRESETS_DIR, reclaim_sudo_ownership
from blockchecks.engine.preset_paths import (
    iter_ipset_files,
    resolve_ipset_file,
)

log = logging.getLogger(__name__)

IpNetwork = IPv4Network | IPv6Network

_FALLBACK_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")

# Baked RFC minimum — used when sinkhole.txt is missing or unreadable.
_BAKED_SINKHOLE = (
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "192.0.2.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "240.0.0.0/4",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "::/128",
    "2001:db8::/32",
    "fc00::/7",
)
_BAKED_CGNAT = ("100.64.0.0/10",)
_BAKED_FALLBACKS = {
    "voice": ("35.217.5.42", 50006),
    "voice_preflight": ("35.217.42.214", 50004),
    "ggc": ("64.233.161.198", None),
}

_CDN_DEFAULTS = (
    "cdn-cloudflare.txt",
    "cdn-google.txt",
    "cdn-fastly.txt",
    "cdn-akamai.txt",
    "cdn-amazon.txt",
    "cdn-discord.txt",
)


@dataclass(frozen=True)
class FallbackEndpoint:
    ip: str
    port: int | None = None


def _lines(path: Path) -> list[str]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("ipset catalog unreadable (%s): %s", path, exc)
        return []
    return [line for raw_line in raw.splitlines() if (line := raw_line.split("#", 1)[0].strip())]


def _parse_network(token: str) -> IpNetwork | None:
    try:
        return ip_network(token, strict=False)
    except ValueError:
        return None


def _nets_from_path(path: Path) -> tuple[IpNetwork, ...]:
    seen: set[str] = set()
    nets: list[IpNetwork] = []
    for line in _lines(path):
        for token in line.replace(",", " ").split():
            net = _parse_network(token)
            if net is None:
                log.warning("ipset skip non-CIDR %s: %s", path, token)
                continue
            key = str(net)
            if key in seen:
                continue
            seen.add(key)
            nets.append(net)
    return tuple(nets)


def _nets_from_tokens(tokens: tuple[str, ...]) -> tuple[IpNetwork, ...]:
    return tuple(ipaddress.ip_network(t, strict=False) for t in tokens)


def _resolve(name: str) -> Path | None:
    override = _ipset_toml().get(name)
    if isinstance(override, str) and override.strip():
        name = Path(override.strip()).stem
    try:
        return resolve_ipset_file(name)
    except (FileNotFoundError, ValueError):
        return None


@lru_cache(maxsize=1)
def sinkhole_nets() -> tuple[IpNetwork, ...]:
    path = _resolve("sinkhole")
    if path is None:
        log.warning("ipset sinkhole.txt missing; using baked RFC nets")
        return _nets_from_tokens(_BAKED_SINKHOLE)
    nets = _nets_from_path(path)
    if not nets:
        log.warning("ipset sinkhole.txt empty/corrupt; using baked RFC nets")
        return _nets_from_tokens(_BAKED_SINKHOLE)
    return nets


@lru_cache(maxsize=1)
def cgnat_nets() -> tuple[IpNetwork, ...]:
    path = _resolve("cgnat")
    if path is None:
        log.warning("ipset cgnat.txt missing; using baked 100.64.0.0/10")
        return _nets_from_tokens(_BAKED_CGNAT)
    nets = _nets_from_path(path)
    if not nets:
        log.warning("ipset cgnat.txt empty/corrupt; using baked 100.64.0.0/10")
        return _nets_from_tokens(_BAKED_CGNAT)
    return nets


@lru_cache(maxsize=1)
def cdn_families() -> tuple[tuple[str, tuple[IpNetwork, ...]], ...]:
    """Ordered (family, nets) from cdn-*.txt; user overlay replaces by basename."""
    names = _cdn_filenames()
    families: list[tuple[str, tuple[IpNetwork, ...]]] = []
    for filename in names:
        stem = filename.removesuffix(".txt")
        family = stem.removeprefix("cdn-") if stem.startswith("cdn-") else stem
        path = _resolve(stem)
        if path is None:
            log.warning("ipset %s missing; family %s empty", filename, family)
            continue
        nets = _nets_from_path(path)
        if not nets:
            log.warning("ipset %s empty/corrupt; family %s empty", filename, family)
            continue
        families.append((family, nets))
    if not families:
        log.warning("ipset no CDN families loaded; anycast match uses /16 only")
    return tuple(families)


def _cdn_filenames() -> tuple[str, ...]:
    extra = _settings_cdn_files()
    if extra:
        return extra
    discovered = tuple(p.name for p in iter_ipset_files(prefix="cdn-"))
    return discovered or _CDN_DEFAULTS


def _settings_cdn_files() -> tuple[str, ...]:
    data = _ipset_toml()
    raw = data.get("cdn")
    if not isinstance(raw, list) or not raw:
        return ()
    names: list[str] = []
    for item in raw:
        text = str(item).strip()
        if not text:
            continue
        names.append(text if text.endswith(".txt") else f"{text}.txt")
    return tuple(names)


@lru_cache(maxsize=1)
def expect_families() -> dict[str, tuple[IpNetwork, ...]]:
    path = _resolve("expect")
    if path is None:
        log.warning("ipset expect.txt missing; AS/org mismatch checks disabled")
        return {}
    grouped: dict[str, list[IpNetwork]] = {}
    seen: dict[str, set[str]] = {}
    for line in _lines(path):
        tokens = line.replace(",", " ").split()
        if len(tokens) < 2 or "." not in tokens[0]:
            log.warning("ipset expect skip %s: %s", path, line)
            continue
        domain = tokens[0].lower()
        bucket = grouped.setdefault(domain, [])
        keys = seen.setdefault(domain, set())
        for token in tokens[1:]:
            net = _parse_network(token)
            if net is None:
                log.warning("ipset expect skip CIDR %s: %s", path, token)
                continue
            key = str(net)
            if key in keys:
                continue
            keys.add(key)
            bucket.append(net)
    return {dom: tuple(nets) for dom, nets in grouped.items() if nets}


@lru_cache(maxsize=1)
def fallbacks() -> dict[str, FallbackEndpoint]:
    baked = {
        name: FallbackEndpoint(ip, port) for name, (ip, port) in _BAKED_FALLBACKS.items()
    }
    path = _resolve("fallbacks")
    if path is None:
        log.warning("ipset fallbacks.txt missing; using baked endpoints")
        return baked
    parsed: dict[str, FallbackEndpoint] = {}
    for line in _lines(path):
        parts = line.split()
        if len(parts) < 2 or not _FALLBACK_KEY_RE.match(parts[0]):
            log.warning("ipset fallback skip %s: %s", path, line)
            continue
        key, value = parts[0], parts[1]
        ep = _parse_endpoint(value)
        if ep is None:
            log.warning("ipset fallback skip %s: %s", path, value)
            continue
        parsed[key] = ep
    if not parsed:
        log.warning("ipset fallbacks.txt empty/corrupt; using baked endpoints")
        return baked
    return {**baked, **parsed}


def _parse_endpoint(value: str) -> FallbackEndpoint | None:
    host, _, port_s = value.rpartition(":")
    if host and port_s.isdigit():
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return None
        return FallbackEndpoint(host, int(port_s))
    try:
        ipaddress.ip_address(value)
    except ValueError:
        net = _parse_network(value)
        if net is None:
            return None
        return FallbackEndpoint(str(net.network_address))
    return FallbackEndpoint(value)


def fallback_endpoint(name: str) -> FallbackEndpoint:
    table = fallbacks()
    if name in table:
        return table[name]
    if name in _BAKED_FALLBACKS:
        ip, port = _BAKED_FALLBACKS[name]
        return FallbackEndpoint(ip, port)
    raise KeyError(name)


def ip_in_nets(ip: str, nets: tuple[IpNetwork, ...]) -> bool:
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    return any(addr in net for net in nets)


def cdn_family(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    return next(
        (name for name, nets in cdn_families() if any(addr in net for net in nets)),
        None,
    )


def clear_ipset_caches() -> None:
    """Public invalidate for all ipset catalog ``lru_cache`` readers.

    Call after env/TOML/overlay changes so file-backed catalogs reload (tests,
    :func:`apply_ipset_fallbacks`).
    """
    sinkhole_nets.cache_clear()
    cgnat_nets.cache_clear()
    cdn_families.cache_clear()
    expect_families.cache_clear()
    fallbacks.cache_clear()
    _ipset_toml.cache_clear()


def clear_ipset_cache() -> None:
    """Backward-compatible alias for :func:`clear_ipset_caches`."""
    clear_ipset_caches()


@lru_cache(maxsize=1)
def _ipset_toml() -> dict:
    from blockchecks.engine.paths import CONFIG_FILE

    if not CONFIG_FILE.is_file():
        return {}
    try:
        import tomllib
    except ImportError:  # pragma: no cover
        import tomli as tomllib  # type: ignore[no-redef]
    try:
        with CONFIG_FILE.open("rb") as f:
            data = tomllib.load(f)
    except OSError:
        return {}
    section = data.get("ipset") if isinstance(data, dict) else None
    return section if isinstance(section, dict) else {}


def seed_user_overlay() -> None:
    """Copy bundled ipset catalogs into the user overlay when missing."""
    dest = USER_PRESETS_DIR / "ipset"
    dest.mkdir(parents=True, exist_ok=True)
    reclaim_sudo_ownership(dest)
    from blockchecks.engine.config import PROJECT_DIR

    src = Path(PROJECT_DIR) / "presets" / "ipset"
    if not src.is_dir():
        return
    for path in src.glob("*.txt"):
        target = dest / path.name
        if target.exists():
            continue
        try:
            shutil.copy2(path, target)
            reclaim_sudo_ownership(target)
        except OSError as exc:
            log.warning("ipset overlay copy failed (%s): %s", target, exc)


def apply_ipset_fallbacks() -> None:
    """Overlay config.DEFAULT_VOICE_* / GGC_FALLBACK_IP from fallbacks.txt."""
    import os

    from blockchecks.engine import config as cfg

    clear_ipset_cache()
    raw = _ipset_toml().get("dir")
    if isinstance(raw, str) and (d := raw.strip()):
        os.environ.setdefault(
            "BLOCKCHECKS_IPSET_DIR", str(Path(os.path.expanduser(d)))
        )
    voice = fallback_endpoint("voice")
    cfg.DEFAULT_VOICE_IP = voice.ip
    if voice.port:
        cfg.DEFAULT_VOICE_PORT = voice.port
    if not os.environ.get("BLOCKCHECKS_GGC_IP", "").strip():
        cfg.GGC_FALLBACK_IP = fallback_endpoint("ggc").ip
