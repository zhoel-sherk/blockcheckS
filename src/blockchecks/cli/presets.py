"""Domain and strategy preset listing + path jail (CLI façade)."""

from __future__ import annotations

import glob
import logging
import os
from pathlib import Path

from blockchecks.engine.config import PROJECT_DIR
from blockchecks.engine.paths import USER_PRESETS_DIR
from blockchecks.engine.preset_paths import (
    RESERVED_DOMAIN_FILES,
    PresetPathError,
    normalize_preset_name,
    resolve_domain_preset,
    resolve_strategy_preset,
)
from blockchecks.terminal import CYAN, RESET

log = logging.getLogger(__name__)

__all__ = [
    "PresetPathError",
    "normalize_preset_name",
    "resolve_domain_preset",
    "resolve_strategy_preset",
    "list_presets",
]


def list_presets() -> None:
    """Print available domain and strategy presets."""
    print(f"{CYAN}Domain presets (presets/domains/):{RESET}")
    for f in sorted(glob.glob(os.path.join(PROJECT_DIR, "presets/domains", "*.txt"))):
        if os.path.basename(f) in RESERVED_DOMAIN_FILES:
            continue
        name = os.path.basename(f).replace(".txt", "")
        with open(f) as pf:
            count = sum(1 for line in pf if line.strip() and not line.startswith("#"))
        print(f"  {name:25s} {count} domains")
    user_dom = Path(USER_PRESETS_DIR) / "domains"
    if user_dom.is_dir():
        print(f"{CYAN}User domain presets ({user_dom}):{RESET}")
        for f in sorted(user_dom.glob("*.txt")):
            if f.name in RESERVED_DOMAIN_FILES:
                continue
            with open(f) as pf:
                count = sum(1 for line in pf if line.strip() and not line.startswith("#"))
            print(f"  {f.stem:25s} {count} domains")
    print(f"{CYAN}Strategy presets (presets/strategies/):{RESET}")
    strategy_exts = (".tls", ".txt", ".http", ".quic", ".udp")
    for f in sorted(
        path
        for ext in strategy_exts
        for path in glob.glob(os.path.join(PROJECT_DIR, "presets/strategies", f"*{ext}"))
    ):
        name = os.path.basename(f)
        for ext in strategy_exts:
            if name.endswith(ext):
                name = name[: -len(ext)]
                break
        with open(f) as pf:
            count = sum(1 for line in pf if line.strip() and not line.startswith("#"))
        print(f"  {name:25s} {count} strategies")
