"""XDG Base Directory paths for blockcheckS runtime data.

Implements XDG Base Directory Specification v0.8 (May 2021):
    https://specifications.freedesktop.org/basedir-spec/latest/

Per-spec requirements:
- All env-var paths must be absolute; relative paths are ignored.
- Empty string env-var values fall back to the spec default.
- ``$XDG_STATE_HOME`` (default ``~/.local/state``) holds state databases.
- ``$XDG_DATA_HOME`` (default ``~/.local/share``) holds data files.
- ``$XDG_CONFIG_HOME`` (default ``~/.config``) holds config.
- ``$XDG_CACHE_HOME`` (default ``~/.cache``) holds cache.

Project-specific overrides (``BLOCKCHECKS_*_HOME``) take priority
over the standard XDG vars when present and non-empty.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

log = logging.getLogger(__name__)


def _resolve_xdg(
    primary_key: str,
    fallback_key: str,
    default: Path,
) -> Path:
    """Return *default* unless *primary_key* or *fallback_key* is a
    non-empty absolute path in the environment (spec §3)."""
    for key in (primary_key, fallback_key):
        val = os.environ.get(key, "")
        if val:
            p = Path(val)
            if not p.is_absolute():
                continue
            return p
    return default


def _xdg_config_home() -> Path:
    return _resolve_xdg("BLOCKCHECKS_CONFIG_HOME", "XDG_CONFIG_HOME",
                        Path.home() / ".config")


def _xdg_data_home() -> Path:
    return _resolve_xdg("BLOCKCHECKS_DATA_HOME", "XDG_DATA_HOME",
                        Path.home() / ".local" / "share")


def _xdg_state_home() -> Path:
    return _resolve_xdg("BLOCKCHECKS_STATE_HOME", "XDG_STATE_HOME",
                        Path.home() / ".local" / "state")


def _xdg_cache_home() -> Path:
    return _resolve_xdg("BLOCKCHECKS_CACHE_HOME", "XDG_CACHE_HOME",
                        Path.home() / ".cache")


# ── module-level constants ────────────────────────────────────────────

CONFIG_DIR      = _xdg_config_home() / "blockcheckS"
CONFIG_FILE     = CONFIG_DIR / "config.toml"
USER_PRESETS_DIR = CONFIG_DIR / "presets"

STATE_DIR       = _xdg_state_home() / "blockcheckS"
DATA_DIR        = _xdg_data_home()   / "blockcheckS"
CACHE_DIR       = _xdg_cache_home()  / "blockcheckS"

DEFAULT_DB_PATH         = STATE_DIR / "state.db"
# User-facing outputs live under DATA (XDG data files). Legacy 1.0.x used STATE.
_LEGACY_OUT_DIR         = STATE_DIR / "export"
_LEGACY_SHORTLIST_DIR   = STATE_DIR / "shortlists"
DEFAULT_OUT_DIR         = DATA_DIR / "export"
DEFAULT_SHORTLIST_DIR   = DATA_DIR / "shortlists"
RUNTIME_LOGS_DIR        = STATE_DIR / "logs"
USER_DATA_PRESETS_DIR   = STATE_DIR / "presets"  # reserved (ensure_dirs); not imported yet

BLOB_CACHE_DIR          = CACHE_DIR / "blob-cache"
PYCACHE_DIR             = CACHE_DIR / "pycache"
GV_URL_CACHE_FILE       = CACHE_DIR / "bs_gv_url_cache.json"
VOICE_DNS_CACHE_FILE    = CACHE_DIR / "bs_voice_cache.json"
SETTLE_PROFILE_FILE     = CACHE_DIR / "settle_profile.json"


def _dir_nonempty(path: Path) -> bool:
    try:
        next(path.iterdir())
        return True
    except (StopIteration, OSError):
        return False


def resolve_user_output_dir(*, kind: str = "export") -> Path:
    """Return DATA_DIR export/shortlists, or legacy STATE_DIR path if still in use.

    Compat for 1.0.x installs that already wrote under ``~/.local/state/.../export``.
    """
    if kind == "shortlists":
        new, legacy = DEFAULT_SHORTLIST_DIR, _LEGACY_SHORTLIST_DIR
    else:
        new, legacy = DEFAULT_OUT_DIR, _LEGACY_OUT_DIR
    if legacy.is_dir() and _dir_nonempty(legacy) and not _dir_nonempty(new):
        return legacy
    return new


def expand_path(value: str | Path | None, *, default: Path) -> Path:
    """Expand ~ and env vars; fall back to default when value is empty."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return default.expanduser().resolve()
    return Path(os.path.expandvars(os.path.expanduser(str(value)))).resolve()


def ensure_dirs() -> None:
    """Create XDG runtime directories (idempotent)."""
    for path in (
        CONFIG_DIR,
        USER_PRESETS_DIR,  # reserved for user config presets
        STATE_DIR,
        DATA_DIR,
        DEFAULT_OUT_DIR,
        DEFAULT_SHORTLIST_DIR,
        RUNTIME_LOGS_DIR,
        USER_DATA_PRESETS_DIR,  # reserved for runtime-imported presets
        CACHE_DIR,
        BLOB_CACHE_DIR,
        PYCACHE_DIR,
        _LEGACY_OUT_DIR,  # still create for compat readers
        _LEGACY_SHORTLIST_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)
        reclaim_sudo_ownership(path)


def reclaim_sudo_ownership(path: Path) -> None:
    """If running as root via sudo, chown *path* back to SUDO_UID/GID.

    Prevents root-owned state.db / export dirs that user-space tools
    (bc-nfconf, shortlist_import) cannot write.
    """
    if os.geteuid() != 0:
        return
    uid_s = os.environ.get("SUDO_UID", "").strip()
    gid_s = os.environ.get("SUDO_GID", "").strip()
    if not uid_s or not gid_s:
        return
    try:
        uid, gid = int(uid_s), int(gid_s)
    except ValueError:
        return
    try:
        os.chown(path, uid, gid)
    except OSError as e:
        log.warning("chown failed for %s: %s", path, e)
        return
    # SQLite sidecars when *path* is the db file
    if path.is_file():
        for suffix in ("-wal", "-shm", "-journal"):
            side = Path(str(path) + suffix)
            if side.exists():
                try:
                    os.chown(side, uid, gid)
                except OSError as e:
                    log.warning("chown failed for %s: %s", side, e)


def apply_pycache_prefix() -> None:
    """Isolate .pyc writes under XDG cache (main process)."""
    ensure_dirs()
    prefix = str(PYCACHE_DIR)
    if hasattr(sys, "pycache_prefix"):
        if not sys.pycache_prefix:
            sys.pycache_prefix = prefix
    os.environ.setdefault("PYTHONPYCACHEPREFIX", prefix)


def subprocess_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """Return env for child Python/subprocess workers with isolated pycache.

    If *base* already sets ``PYTHONPYCACHEPREFIX``, that value is preserved.
    """
    env = dict(os.environ)
    if base:
        env.update(base)
        if "PYTHONPYCACHEPREFIX" in base:
            return env
    env["PYTHONPYCACHEPREFIX"] = str(PYCACHE_DIR)
    return env
