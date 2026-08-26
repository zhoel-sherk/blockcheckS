"""Validate BLOCKCHECKS_* env and user config.toml."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from blockchecks.engine.config import ZAPRET2_ROOT
from blockchecks.engine.paths import CONFIG_FILE

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]

_DEFAULT_NFQWS2 = os.path.join(ZAPRET2_ROOT, "nfq2", "nfqws2")
_DEFAULT_BLOBS = os.path.join(ZAPRET2_ROOT, "blobs")
_DEFAULT_LUA = os.path.join(ZAPRET2_ROOT, "lua")


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
    doh_servers: list[dict[str, Any]] = Field(default_factory=list)
    udp_servers: list[dict[str, Any]] = Field(default_factory=list)
    proxy: str = ""
    unblocked_dom: str = "ripe.net"
    curl_parallel: int = 1
    wall_slack: float = 3.0


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
    if isinstance(run, dict) and "wall_slack" in run and not os.environ.get("BLOCKCHECKS_WALL_SLACK"):
        out["wall_slack"] = float(run["wall_slack"])
    secure = data.get("secure_dns") or {}
    if isinstance(secure, dict):
        if "enabled" in secure and not os.environ.get("BLOCKCHECKS_SECURE_DNS"):
            out["secure_dns"] = bool(secure["enabled"])
        if secure.get("doh_server") and not os.environ.get("BLOCKCHECKS_DOH_SERVER"):
            out["doh_server"] = str(secure["doh_server"])
        if servers := _doh_entries(secure.get("servers")):
            out["doh_servers"] = servers
        if udp := _udp_entries(secure.get("udp")):
            out["udp_servers"] = udp
    return out


def _doh_entries(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    return [e for x in raw if (e := _one_doh(x))]


def _one_doh(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, str) and raw.strip().startswith("http"):
        url = raw.strip()
        host = (urlsplit(url).hostname or url).lower()
        return {"name": host, "url": url, "ip": "", "trusted": True}
    if not isinstance(raw, dict):
        return None
    url = str(raw.get("url") or "").strip()
    if not url.startswith("http"):
        return None
    trusted = True if "trusted" not in raw else bool(raw["trusted"])
    if raw.get("untrusted"):
        trusted = False
    host = (urlsplit(url).hostname or url).lower()
    return {
        "name": str(raw.get("name") or "").strip() or host,
        "url": url,
        "ip": str(raw.get("ip") or "").strip(),
        "trusted": trusted,
    }


def _udp_entries(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    return [e for x in raw if (e := _one_udp(x))]


def _one_udp(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, str):
        parts = raw.strip().split()
        if not parts:
            return None
        return {"ip": parts[0], "name": " ".join(parts[1:]) or parts[0]}
    if not isinstance(raw, dict):
        return None
    ip = str(raw.get("ip") or "").strip()
    if not ip:
        return None
    return {"ip": ip, "name": str(raw.get("name") or "").strip() or ip}


@lru_cache(maxsize=1)
def load_settings(*, config_path: str | None = None) -> BlockchecksSettings:
    """Cached settings: env + optional ~/.config/blockcheckS/config.toml."""
    path = Path(config_path) if config_path else None
    overlay = _overlay_from_toml(_load_user_toml(path))
    return BlockchecksSettings(**overlay)


def clear_settings_cache() -> None:
    """Public invalidate for :func:`load_settings` ``lru_cache``.

    Call after ``BLOCKCHECKS_*`` env or ``config.toml`` changes so the next
    :func:`load_settings` read picks up fresh values (tests, ``user_config``).
    """
    load_settings.cache_clear()


def apply_settings_env(settings: BlockchecksSettings | None = None) -> BlockchecksSettings:
    """Copy settings into os.environ for config.py readers."""
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
    os.environ.setdefault("BLOCKCHECKS_WALL_SLACK", str(s.wall_slack))
    google = _load_user_toml().get("google")
    if isinstance(google, dict):
        mode = str(google.get("mode") or "").strip().lower()
        if mode in ("synthetic", "real", "fixed"):
            os.environ.setdefault("BLOCKCHECKS_GGC_MODE", mode)
    _apply_doh_catalog(s)
    return s


def _apply_doh_catalog(s: BlockchecksSettings) -> None:
    """Replace in-memory DoH/UDP catalogs when the user listed servers."""
    from blockchecks.engine import config as cfg

    if s.doh_servers:
        cfg.DOH_SERVERS[:] = [(e["url"], e["name"] or e["url"]) for e in s.doh_servers]
        cfg.UNTRUSTED_DOH_URLS.clear()
        cfg.UNTRUSTED_DOH_URLS.update(
            e["url"].rstrip("/") for e in s.doh_servers if not e.get("trusted", True)
        )
        cfg.DOH_BOOTSTRAP.clear()
        cfg.DOH_BOOTSTRAP.update(
            {
                host: e["ip"]
                for e in s.doh_servers
                if e.get("ip") and (host := (urlsplit(e["url"]).hostname or "").lower())
            }
        )
    if s.udp_servers:
        cfg.UDP_DNS_SERVERS[:] = [(e["ip"], e["name"] or e["ip"]) for e in s.udp_servers]
    from blockchecks.engine.ipset_catalog import apply_ipset_fallbacks

    apply_ipset_fallbacks()
