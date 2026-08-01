"""Domain and strategy preset listing."""

import glob
import os

from colorama import Fore, Style

from blockchecks.engine.config import PROJECT_DIR

RESET = Style.RESET_ALL


def list_presets() -> None:
    """Print available domain and strategy presets."""
    print(f"{Fore.CYAN}Domain presets (presets/domains/):{RESET}")
    for f in sorted(glob.glob(os.path.join(PROJECT_DIR, "presets/domains", "*.txt"))):
        name = os.path.basename(f).replace(".txt", "")
        with open(f) as pf:
            count = sum(1 for line in pf if line.strip() and not line.startswith("#"))
        print(f"  {name:25s} {count} domains")
    print(f"{Fore.CYAN}Strategy presets (presets/strategies/):{RESET}")
    for f in sorted(
        glob.glob(os.path.join(PROJECT_DIR, "presets/strategies", "*.tls"))
        + glob.glob(os.path.join(PROJECT_DIR, "presets/strategies", "*.txt"))
    ):
        name = os.path.basename(f)
        for ext in (".tls", ".txt"):
            if name.endswith(ext):
                name = name[: -len(ext)]
                break
        with open(f) as pf:
            count = sum(1 for line in pf if line.strip() and not line.startswith("#"))
        print(f"  {name:25s} {count} strategies")
