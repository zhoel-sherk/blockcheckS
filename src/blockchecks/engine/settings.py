"""Typed BLOCKCHECKS_* / config.toml settings (pydantic-settings).

Argparse CLI remains the front door; this module validates env + user TOML.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict

from blockchecks.engine.paths import CONFIG_FILE

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]

_DEFAULT_NFQWS2 = "/opt/zapret2/nfq2/nfqws2"
_DEFAULT_BLOBS = "/opt/zapret2/blobs"
_DEFAULT_LUA = "/opt/zapret2/lua"


class BlockchecksSettings(BaseSettings):
    """Runtime settings: env BLOCKCHECKS_* wins over config.toml overlays."""

    model_config = SettingsConfigDict(
        env_prefix="BLOCKCHECKS_",
        extra="ignore",
        case_sensitive=False,
    )

    nfqws2: str = _DEFAULT_NFQWS2
    blobs: str = _DEFAULT_BLOBS
    lua_dir: str = _DEFAULT_LUA
    pool: int = 4
    secure_dns: bool = True
    doh_server: str = ""
    proxy: str = "socks5://127.0.0.1:11080"
    unblocked_dom: str = "iana.org"
    curl_parallel: int = 1


def _load_user_toml(path: Path | None = None) -> dict[str, Any]:
    cfg_path = path or CONFIG_FILE
    if not cfg_path.is_file():
        return {}
    with cfg_path.open("rb") as f:
        data = tomllib.load(f)
    return data if isinstance(data, dict) else {}


def _overlay_from_toml(data: dict[str, Any]) -> dict[str, Any]:
    """Map config.toml sections → Settings kwargs when env is unset."""
    out: dict[str, Any] = {}
    tools = data.get("tools") or {}
    if isinstance(tools, dict):
        mapping = (
            ("nfqws2", "nfqws2", "BLOCKCHECKS_NFQWS2"),
            ("blobs", "blobs", "BLOCKCHECKS_BLOBS"),
            ("lua_dir", "lua_dir", "BLOCKCHECKS_LUA_DIR"),
            ("proxy", "proxy", "BLOCKCHECKS_PROXY"),
        )
        for toml_key, field, env_key in mapping:
            if tools.get(toml_key) and not os.environ.get(env_key):
                out[field] = tools[toml_key]
    run = data.get("run") or {}
    if isinstance(run, dict) and "parallel" in run and not os.environ.get("BLOCKCHECKS_POOL"):
        out["pool"] = int(run["parallel"])
    secure = data.get("secure_dns") or {}
    if isinstance(secure, dict):
        if "enabled" in secure and not os.environ.get("BLOCKCHECKS_SECURE_DNS"):
            out["secure_dns"] = bool(secure["enabled"])
        if secure.get("doh_server") and not os.environ.get("BLOCKCHECKS_DOH_SERVER"):
            out["doh_server"] = str(secure["doh_server"])
    return out


@lru_cache(maxsize=1)
def load_settings(*, config_path: str | None = None) -> BlockchecksSettings:
    """Cached settings: env + optional ~/.config/blockcheckS/config.toml."""
    path = Path(config_path) if config_path else None
    overlay = _overlay_from_toml(_load_user_toml(path))
    return BlockchecksSettings(**overlay)


def clear_settings_cache() -> None:
    load_settings.cache_clear()


def apply_settings_env(settings: BlockchecksSettings | None = None) -> BlockchecksSettings:
    """Push settings into os.environ so legacy config.py readers stay consistent."""
    s = settings or load_settings()
    os.environ.setdefault("BLOCKCHECKS_NFQWS2", s.nfqws2)
    os.environ.setdefault("BLOCKCHECKS_BLOBS", s.blobs)
    os.environ.setdefault("BLOCKCHECKS_LUA_DIR", s.lua_dir)
    os.environ.setdefault("BLOCKCHECKS_POOL", str(s.pool))
    os.environ.setdefault("BLOCKCHECKS_SECURE_DNS", "1" if s.secure_dns else "0")
    if s.doh_server:
        os.environ.setdefault("BLOCKCHECKS_DOH_SERVER", s.doh_server)
    os.environ.setdefault("BLOCKCHECKS_PROXY", s.proxy)
    os.environ.setdefault("BLOCKCHECKS_UNBLOCKED_DOM", s.unblocked_dom)
    os.environ.setdefault("BLOCKCHECKS_CURL_PARALLEL", str(s.curl_parallel))
    return s
