"""User config.toml loader for blockcheckS CLI defaults."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]

from blockchecks.engine.paths import CONFIG_FILE, DEFAULT_DB_PATH, DEFAULT_OUT_DIR, expand_path


def load_user_config(path: Path | None = None) -> dict[str, Any]:
    """Load ~/.config/blockcheckS/config.toml (empty dict if missing)."""
    cfg_path = path or CONFIG_FILE
    if not cfg_path.is_file():
        return {}
    with cfg_path.open("rb") as f:
        data = tomllib.load(f)
    return data if isinstance(data, dict) else {}


def resolve_store_path(value: str | None, cfg: dict[str, Any], key: str, default: Path) -> str:
    """Resolve db/out_dir: explicit CLI > config.toml > XDG default."""
    if value:
        return str(expand_path(value, default=default))
    paths = cfg.get("paths") or {}
    if isinstance(paths, dict) and paths.get(key):
        return str(expand_path(paths[key], default=default))
    return str(default)


def apply_parser_defaults(parser: argparse.ArgumentParser, cfg: dict[str, Any]) -> None:
    """Merge config.toml defaults into argparse (lower priority than CLI)."""
    from blockchecks.engine.settings import apply_settings_env, clear_settings_cache, load_settings

    clear_settings_cache()
    # Ensure [secure_dns] / [tools] from cfg path are visible via settings overlay.
    settings = load_settings()
    apply_settings_env(settings)
    from blockchecks.engine.config import refresh_secure_dns_from_env

    refresh_secure_dns_from_env()

    defaults: dict[str, Any] = {}
    paths = cfg.get("paths") or {}
    if isinstance(paths, dict):
        if paths.get("db"):
            defaults["db"] = str(expand_path(paths["db"], default=DEFAULT_DB_PATH))
        if paths.get("out_dir"):
            defaults["out_dir"] = str(expand_path(paths["out_dir"], default=DEFAULT_OUT_DIR))
    run = cfg.get("run") or {}
    if isinstance(run, dict):
        for key in (
            "parallel",
            "scan_level",
            "timeout",
            "max",
            "bridge_batch",
            "adaptive_epsilon",
            "max_timeh",
            "max_timem",
        ):
            if key in run:
                defaults[key] = run[key]
        # Non-CLI run settings → env for engine readers.
        env_map = {
            "retry_ip_timeout": "BLOCKCHECKS_RETRY_IP_TIMEOUT",
            "domain_isolate": "BLOCKCHECKS_AQ_DOMAIN_ISOLATE",
            "bridge_batch": "BLOCKCHECKS_BRIDGE_BATCH",
        }
        for key, env_name in env_map.items():
            if key in run and not os.environ.get(env_name):
                os.environ[env_name] = str(run[key])
    tools = cfg.get("tools") or {}
    if isinstance(tools, dict):
        if tools.get("nfqws2") and not os.environ.get("BLOCKCHECKS_NFQWS2"):
            os.environ.setdefault("BLOCKCHECKS_NFQWS2", str(tools["nfqws2"]))
        if tools.get("blobs") and not os.environ.get("BLOCKCHECKS_BLOBS"):
            os.environ.setdefault("BLOCKCHECKS_BLOBS", str(tools["blobs"]))
        if tools.get("lua_dir") and not os.environ.get("BLOCKCHECKS_LUA_DIR"):
            os.environ.setdefault("BLOCKCHECKS_LUA_DIR", str(tools["lua_dir"]))
        from blockchecks.engine.config import apply_tool_paths

        apply_tool_paths()
    # Apply secure_dns defaults onto argparse when flags absent
    secure = cfg.get("secure_dns") or {}
    if isinstance(secure, dict) and secure.get("doh_server") and "doh_server" not in defaults:
        defaults["doh_server"] = str(secure["doh_server"])
    if defaults:
        parser.set_defaults(**defaults)


def finalize_store_args(args: argparse.Namespace, cfg: dict[str, Any]) -> None:
    """Post-parse: fill None db/out_dir from config or XDG defaults."""
    if getattr(args, "db", None) is None:
        args.db = resolve_store_path(None, cfg, "db", DEFAULT_DB_PATH)
    elif getattr(args, "db", None):
        args.db = str(expand_path(args.db, default=DEFAULT_DB_PATH))
    if hasattr(args, "out_dir"):
        from blockchecks.engine.paths import resolve_user_output_dir

        out_default = resolve_user_output_dir(kind="export")
        if args.out_dir is None:
            args.out_dir = resolve_store_path(None, cfg, "out_dir", out_default)
        else:
            args.out_dir = str(expand_path(args.out_dir, default=out_default))
