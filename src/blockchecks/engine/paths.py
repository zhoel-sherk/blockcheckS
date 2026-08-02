"""XDG Base Directory paths for blockcheckS runtime data."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _xdg_config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))


def _xdg_data_home() -> Path:
    override = os.environ.get("BLOCKCHECKS_DATA_HOME") or os.environ.get("XDG_DATA_HOME")
    if override:
        return Path(override)
    return Path.home() / ".local" / "share"


def _xdg_cache_home() -> Path:
    override = os.environ.get("BLOCKCHECKS_CACHE_HOME") or os.environ.get("XDG_CACHE_HOME")
    if override:
        return Path(override)
    return Path.home() / ".cache"


CONFIG_DIR = Path(os.environ.get("BLOCKCHECKS_CONFIG_HOME", _xdg_config_home() / "blockcheckS"))
CONFIG_FILE = CONFIG_DIR / "config.toml"
USER_PRESETS_DIR = CONFIG_DIR / "presets"

DATA_DIR = Path(_xdg_data_home()) / "blockcheckS"
CACHE_DIR = Path(_xdg_cache_home()) / "blockcheckS"

DEFAULT_DB_PATH = DATA_DIR / "state.db"
DEFAULT_OUT_DIR = DATA_DIR / "export"
DEFAULT_SHORTLIST_DIR = DATA_DIR / "shortlists"
RUNTIME_LOGS_DIR = DATA_DIR / "logs"
USER_DATA_PRESETS_DIR = DATA_DIR / "presets"

BLOB_CACHE_DIR = CACHE_DIR / "blob-cache"
PYCACHE_DIR = CACHE_DIR / "pycache"
GV_URL_CACHE_FILE = CACHE_DIR / "bs_gv_url_cache.json"
VOICE_DNS_CACHE_FILE = CACHE_DIR / "bs_voice_cache.json"
SETTLE_PROFILE_FILE = CACHE_DIR / "settle_profile.json"


def expand_path(value: str | Path | None, *, default: Path) -> Path:
    """Expand ~ and env vars; fall back to default when value is empty."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return default.expanduser().resolve()
    return Path(os.path.expandvars(os.path.expanduser(str(value)))).resolve()


def ensure_dirs() -> None:
    """Create XDG runtime directories (idempotent)."""
    for path in (
        CONFIG_DIR,
        USER_PRESETS_DIR,
        DATA_DIR,
        DEFAULT_OUT_DIR,
        DEFAULT_SHORTLIST_DIR,
        RUNTIME_LOGS_DIR,
        USER_DATA_PRESETS_DIR,
        CACHE_DIR,
        BLOB_CACHE_DIR,
        PYCACHE_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)


def apply_pycache_prefix() -> None:
    """Isolate .pyc writes under XDG cache (main process)."""
    ensure_dirs()
    prefix = str(PYCACHE_DIR)
    if hasattr(sys, "pycache_prefix"):
        if not sys.pycache_prefix:
            sys.pycache_prefix = prefix
    os.environ.setdefault("PYTHONPYCACHEPREFIX", prefix)


def subprocess_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """Return env for child Python/subprocess workers with isolated pycache."""
    env = dict(os.environ)
    if base:
        env.update(base)
    env.setdefault("PYTHONPYCACHEPREFIX", str(PYCACHE_DIR))
    env["PYTHONPYCACHEPREFIX"] = str(PYCACHE_DIR)
    return env
