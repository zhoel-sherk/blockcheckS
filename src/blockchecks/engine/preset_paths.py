"""Preset path jail — shared by engine and CLI (no cli→engine cycle)."""

from __future__ import annotations

import os
import re
from pathlib import Path

from blockchecks.engine.config import PROJECT_DIR
from blockchecks.engine.paths import USER_PRESETS_DIR

# Not selectable as a domain preset (filter list only).
RESERVED_DOMAIN_FILES = frozenset({"denylist.txt"})

# Preset names: simple tokens only (no path separators / traversal).
_PRESET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class PresetPathError(ValueError):
    """Raised when a preset name escapes the allowed directories."""


def _bundled_domains_dir() -> Path:
    return Path(PROJECT_DIR) / "presets" / "domains"


def _bundled_strategies_dir() -> Path:
    return Path(PROJECT_DIR) / "presets" / "strategies"


def _user_domains_dir() -> Path:
    return Path(USER_PRESETS_DIR) / "domains"


def _user_strategies_dir() -> Path:
    return Path(USER_PRESETS_DIR) / "strategies"


def normalize_preset_name(name: str, *, strip_suffixes: tuple[str, ...] = ()) -> str:
    """Return a safe basename token or raise PresetPathError."""
    if not name or not isinstance(name, str):
        raise PresetPathError("empty preset name")
    raw = name.strip()
    if not raw:
        raise PresetPathError("empty preset name")
    # Reject absolute / URL-like / home paths early.
    if raw.startswith(("/", "~")) or "://" in raw:
        raise PresetPathError(f"preset name must not be an absolute path: {name!r}")
    if os.sep in raw or (os.altsep and os.altsep in raw) or ".." in raw.split("/"):
        raise PresetPathError(f"preset name must not contain path components: {name!r}")
    base = Path(raw).name  # strips any residual directory
    if base != raw.replace("\\", "/").rsplit("/", 1)[-1]:
        raise PresetPathError(f"preset name must not contain path components: {name!r}")
    for suf in strip_suffixes:
        if base.endswith(suf):
            base = base[: -len(suf)]
            break
    if not base or base in (".", "..") or not _PRESET_NAME_RE.match(base):
        raise PresetPathError(f"invalid preset name: {name!r}")
    return base


def _resolve_under(root: Path, filename: str) -> Path | None:
    """Return path if file exists and realpath stays under root."""
    root = root.resolve()
    candidate = (root / filename).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise PresetPathError(f"path escapes preset jail: {filename!r}") from None
    if candidate.is_file():
        return candidate
    return None


def resolve_domain_preset(name: str) -> Path:
    """Resolve presets/domains/{name}.txt inside user or bundled jail."""
    base = normalize_preset_name(name, strip_suffixes=(".txt",))
    filename = f"{base}.txt"
    if filename in RESERVED_DOMAIN_FILES:
        raise PresetPathError(f"reserved domain preset: {base!r}")
    for root in (_user_domains_dir(), _bundled_domains_dir()):
        if not root.is_dir():
            continue
        hit = _resolve_under(root, filename)
        if hit is not None:
            return hit
    raise FileNotFoundError(filename)


def resolve_strategy_preset(name: str) -> Path:
    """Resolve presets/strategies/{name}.tls|.txt inside user or bundled jail."""
    base = normalize_preset_name(name, strip_suffixes=(".tls", ".txt", ".quic"))
    for root in (_user_strategies_dir(), _bundled_strategies_dir()):
        if not root.is_dir():
            continue
        for ext in (".tls", ".txt"):
            hit = _resolve_under(root, f"{base}{ext}")
            if hit is not None:
                return hit
    raise FileNotFoundError(base)
