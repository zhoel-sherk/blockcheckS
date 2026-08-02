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
    defaults: dict[str, Any] = {}
    paths = cfg.get("paths") or {}
    if isinstance(paths, dict):
        if paths.get("db"):
            defaults["db"] = str(expand_path(paths["db"], default=DEFAULT_DB_PATH))
        if paths.get("out_dir"):
            defaults["out_dir"] = str(expand_path(paths["out_dir"], default=DEFAULT_OUT_DIR))
    run = cfg.get("run") or {}
    if isinstance(run, dict):
        for key in ("parallel", "scan_level", "timeout", "max"):
            if key in run:
                defaults[key] = run[key]
    tools = cfg.get("tools") or {}
    if isinstance(tools, dict):
        if tools.get("nfqws2") and not os.environ.get("BLOCKCHECKS_NFQWS2"):
            os.environ.setdefault("BLOCKCHECKS_NFQWS2", str(tools["nfqws2"]))
        if tools.get("blobs") and not os.environ.get("BLOCKCHECKS_BLOBS"):
            os.environ.setdefault("BLOCKCHECKS_BLOBS", str(tools["blobs"]))
    if defaults:
        parser.set_defaults(**defaults)


def finalize_store_args(args: argparse.Namespace, cfg: dict[str, Any]) -> None:
    """Post-parse: fill None db/out_dir from config or XDG defaults."""
    if getattr(args, "db", None) is None:
        args.db = resolve_store_path(None, cfg, "db", DEFAULT_DB_PATH)
    elif getattr(args, "db", None):
        args.db = str(expand_path(args.db, default=DEFAULT_DB_PATH))
    if hasattr(args, "out_dir"):
        if args.out_dir is None:
            paths = cfg.get("paths") or {}
            if isinstance(paths, dict) and paths.get("out_dir"):
                args.out_dir = str(expand_path(paths["out_dir"], default=DEFAULT_OUT_DIR))
        elif args.out_dir:
            args.out_dir = str(expand_path(args.out_dir, default=DEFAULT_OUT_DIR))
