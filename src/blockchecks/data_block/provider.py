"""Provider name resolution — auto-detect from ipinfo.io once, then config.toml.

The provider slug selects the folder inside ``data_block/providers/``.
On first start blockcheckS queries https://ipinfo.io/json and writes the
normalized ``org`` string (e.g. ``AS51369 LLC TRC FIORD`` → ``llc_fiord``)
into ``[provider] name`` of config.toml.  Once set, the check is skipped.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

from blockchecks.engine.paths import CONFIG_FILE

DEFAULT_PROVIDER = "default"

# Normalize e.g. "AS51369 LLC TRC FIORD" -> "llc_fiord"
_AS_PREFIX = re.compile(r"^\s*AS\d+\b\s*", re.IGNORECASE)
_NON_SLUG = re.compile(r"[^a-z0-9_]+")

_CACHE: dict[str, str] = {}


def _cached_provider(fn):
    """Memoize provider_name() per (allow_detect) — avoid re-reading config.toml."""

    def wrapper(allow_detect: bool = True) -> str:
        key = str(bool(allow_detect))
        if key not in _CACHE:
            _CACHE[key] = fn(allow_detect=allow_detect)
        return _CACHE[key]

    return wrapper


def normalize_provider_name(org: str) -> str:
    """Turn an ipinfo ``org`` line into a slug-safe provider name."""
    if not org or not org.strip():
        return DEFAULT_PROVIDER
    text = _AS_PREFIX.sub("", org).strip().lower()
    text = _NON_SLUG.sub("_", text).strip("_")
    return text or DEFAULT_PROVIDER


def _query_ipinfo(timeout: float = 5.0) -> str | None:
    """Return ``org`` from ipinfo.io, or None on any failure."""
    try:
        with urllib.request.urlopen(
            "https://ipinfo.io/json", timeout=timeout
        ) as resp:
            data = json.load(resp)
        org = data.get("org") if isinstance(data, dict) else None
        return str(org).strip() if org else None
    except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError):
        return None


def _read_provider_from_cfg() -> str:
    try:
        import tomllib
    except ImportError:  # pragma: no cover
        return ""
    if not CONFIG_FILE.is_file():
        return ""
    try:
        with CONFIG_FILE.open("rb") as f:
            data = tomllib.load(f)
        prov = data.get("provider") or {}
        if isinstance(prov, dict) and prov.get("name"):
            return str(prov["name"]).strip()
    except Exception:
        return ""
    return ""


def _write_provider_to_cfg(name: str) -> None:
    """Atomically set ``[provider] name`` in config.toml (preserve other keys).

    Written by hand (no ``tomli_w`` dependency): merge ``[provider] name`` into
    the existing TOML without reformatting unrelated sections.
    """
    from blockchecks.engine.paths import reclaim_sudo_ownership

    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    raw = ""
    try:
        if CONFIG_FILE.is_file():
            raw = CONFIG_FILE.read_text(encoding="utf-8")
    except OSError:
        raw = ""
    lines = raw.splitlines()
    out: list[str] = []
    in_provider = False
    provider_seen = False
    replaced = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_provider = stripped == "[provider]"
            if in_provider:
                provider_seen = True
            out.append(line)
            continue
        if in_provider and not replaced:
            if stripped == "" or stripped.startswith("["):
                out.append(f'name = "{name}"')
                out.append("")
                replaced = True
            elif stripped.startswith("name"):
                out.append(f'name = "{name}"')
                replaced = True
                continue
        out.append(line)
    if not provider_seen:
        if out and out[-1].strip():
            out.append("")
        out.append('[provider]')
        out.append(f'name = "{name}"')
    elif not replaced:
        out.append(f'name = "{name}"')
    tmp = CONFIG_FILE.with_suffix(".toml.tmp")
    tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
    tmp.replace(CONFIG_FILE)
    reclaim_sudo_ownership(CONFIG_FILE)


def _ensure_provider_config(allow_detect: bool = True) -> str:
    """Return the configured provider name, auto-detecting once if missing."""
    existing = _read_provider_from_cfg()
    if existing:
        return existing
    env_override = os.environ.get("BLOCKCHECKS_PROVIDER", "").strip()
    if env_override:
        _write_provider_to_cfg(env_override)
        return env_override
    if not allow_detect:
        return DEFAULT_PROVIDER
    org = _query_ipinfo()
    if not org:
        print(
            "  WARNING: could not detect provider via ipinfo.io; "
            "data_block sync disabled for this run"
        )
        return DEFAULT_PROVIDER
    slug = normalize_provider_name(org)
    _write_provider_to_cfg(slug)
    print(f"  [data_block] provider detected: {org} -> {slug}")
    return slug


@_cached_provider
def provider_name(allow_detect: bool = True) -> str:
    """Current provider slug (auto-detect once, then config.toml)."""
    return _ensure_provider_config(allow_detect=allow_detect)


def get_provider_dir(allow_detect: bool = True) -> Path:
    """Directory ``<repo>/data_block/providers/<provider>`` for this host."""
    from blockchecks.engine.config import PROJECT_DIR

    name = provider_name(allow_detect=allow_detect)
    return Path(PROJECT_DIR) / "data_block" / "providers" / name
