"""Resolve the provider slug from ipinfo.io once, then keep it in config.toml."""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

from blockchecks.engine.paths import CONFIG_FILE

log = logging.getLogger(__name__)


DEFAULT_PROVIDER = "default"

# Normalize e.g. "AS51369 LLC TRC FIORD" -> "llc_fiord"
_AS_PREFIX = re.compile(r"^\s*AS\d+\b\s*", re.IGNORECASE)
_NON_SLUG = re.compile(r"[^a-z0-9_]+")

_CACHE: dict[str, str] = {}
_SKIP_DETECT_WARNED = False


def _cached_provider(fn):
    """Memoize provider_name() per (allow_detect) — avoid re-reading config.toml.

    Soft defaults (detect skipped / ipinfo failed) are never cached so a later
    config.toml write or successful detect can take effect in-process.
    """

    def wrapper(allow_detect: bool = True) -> str:
        from_cfg = _read_provider_from_cfg()
        if from_cfg:
            key = str(bool(allow_detect))
            _CACHE[key] = from_cfg
            return from_cfg
        key = str(bool(allow_detect))
        cached = _CACHE.get(key)
        if cached is not None and cached != DEFAULT_PROVIDER:
            return cached
        result = fn(allow_detect=allow_detect)
        if result != DEFAULT_PROVIDER:
            _CACHE[key] = result
        else:
            _CACHE.pop(key, None)
        return result

    return wrapper


def normalize_provider_name(org: str) -> str:
    """Turn an ipinfo ``org`` line into a slug-safe provider name."""
    if not org or not org.strip():
        log.warning("%s", "  WARNING: empty ipinfo org; using provider default")
        return DEFAULT_PROVIDER
    text = _AS_PREFIX.sub("", org).strip().lower()
    text = _NON_SLUG.sub("_", text).strip("_")
    if not text:
        log.warning("%s", "  WARNING: org slug empty; using provider default")
        return DEFAULT_PROVIDER
    return text


def _query_ipinfo(timeout: float = 5.0) -> str | None:
    """Return ``org`` from ipinfo.io, or None on any failure."""
    try:
        with urllib.request.urlopen("https://ipinfo.io/json", timeout=timeout) as resp:
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
    except Exception as exc:
        log.warning("%s", f"  WARNING: config.toml provider unreadable ({exc})")
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
        out.append("[provider]")
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
        global _SKIP_DETECT_WARNED
        if not _SKIP_DETECT_WARNED:
            log.warning("%s", "  WARNING: provider detect skipped; using default")
            _SKIP_DETECT_WARNED = True
        return DEFAULT_PROVIDER
    org = _query_ipinfo()
    if not org:
        log.warning(
            "  WARNING: could not detect provider via ipinfo.io; "
            "data_block sync disabled for this run"
        )
        return DEFAULT_PROVIDER
    slug = normalize_provider_name(org)
    _write_provider_to_cfg(slug)
    log.info("%s", f"  [data_block] provider detected: {org} -> {slug}")
    return slug


@_cached_provider
def provider_name(allow_detect: bool = True) -> str:
    """Current provider slug (auto-detect once, then config.toml)."""
    return _ensure_provider_config(allow_detect=allow_detect)


def data_block_runtime_root() -> Path:
    """XDG (or BLOCKCHECKS_DATA_BLOCK) root that contains ``providers/``."""
    from blockchecks.engine.paths import DATA_DIR

    env = os.environ.get("BLOCKCHECKS_DATA_BLOCK", "").strip()
    if env:
        p = Path(os.path.expandvars(os.path.expanduser(env)))
        if p.is_absolute() and not _under_install_prefix(p):
            return p
    return DATA_DIR / "data_block"


def data_block_repo_root() -> Path | None:
    """Checkout of the data_block git repo/submodule, if present."""
    from blockchecks.engine.config import PROJECT_DIR

    for cand in (Path.cwd() / "data_block", Path(PROJECT_DIR) / "data_block"):
        if (cand / ".git").exists():
            return cand
    repo = Path(PROJECT_DIR) / "data_block"
    if (repo / "providers").is_dir() and not _under_install_prefix(repo):
        return repo
    return None


def _under_install_prefix(path: Path) -> bool:
    import sys

    try:
        path.resolve().relative_to(Path(sys.prefix).resolve())
        return True
    except ValueError:
        return False


def _repo_providers() -> Path | None:
    from blockchecks.engine.config import PROJECT_DIR

    src = Path(PROJECT_DIR) / "data_block" / "providers"
    if src.is_dir() and not _under_install_prefix(src):
        return src
    return None


def _provider_slot_empty(path: Path) -> bool:
    if not path.exists():
        return True
    try:
        names = {p.name for p in path.iterdir()}
    except OSError:
        return False
    return not names or names <= {f"{path.name}.md"}


def _copy_provider_tree(src: Path, dest: Path) -> None:
    import shutil

    from blockchecks.engine.paths import reclaim_sudo_ownership

    tmp = dest.with_name(f".{dest.name}.migrating.{os.getpid()}")
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(src, tmp)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        shutil.rmtree(dest)
    tmp.replace(dest)
    reclaim_sudo_ownership(dest)


_MIGRATED = False


def _maybe_migrate_providers() -> None:
    """One-time copy from repo submodule → XDG when the XDG slot is empty."""
    global _MIGRATED
    if _MIGRATED:
        return
    _MIGRATED = True
    src_base = _repo_providers()
    if src_base is None:
        return
    runtime = data_block_runtime_root() / "providers"
    try:
        runtime.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        log.warning("data_block runtime mkdir failed: %s", exc)
        return
    for src in src_base.iterdir():
        if not src.is_dir():
            continue
        dest = runtime / src.name
        if not _provider_slot_empty(dest):
            continue
        try:
            _copy_provider_tree(src, dest)
            log.info("%s", f"  [data_block] migrated {src.name} → {dest}")
        except OSError as exc:
            log.warning("data_block migrate failed (%s): %s", src, exc)


def get_provider_dir(allow_detect: bool = True) -> Path:
    """Directory ``DATA_DIR/data_block/providers/<provider>`` for this host."""
    from blockchecks.engine.paths import reclaim_sudo_ownership

    _maybe_migrate_providers()
    name = provider_name(allow_detect=allow_detect)
    if not isinstance(name, str) or not name:
        name = DEFAULT_PROVIDER
    dest = data_block_runtime_root() / "providers" / name
    dest.mkdir(parents=True, exist_ok=True)
    reclaim_sudo_ownership(dest)
    return dest


def iter_provider_dirs(allow_detect: bool = True) -> list[Path]:
    """All provider dirs under the XDG data_block (agnostic to host provider).

    Returns current provider first (if its dir exists), then every other
    provider dir. Used when aggregating DNS/IP data across providers.
    """
    _maybe_migrate_providers()
    base = data_block_runtime_root() / "providers"
    if not base.is_dir():
        return []
    current = get_provider_dir(allow_detect=allow_detect)
    ordered: list[Path] = []
    seen: set[Path] = set()
    if current.is_dir():
        ordered.append(current)
        seen.add(current)
    for entry in sorted(base.iterdir()):
        if entry.is_dir() and entry not in seen:
            ordered.append(entry)
    return ordered
