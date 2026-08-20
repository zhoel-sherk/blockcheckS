"""Terminal colors and user-facing print helpers."""

from __future__ import annotations

import os
import sys
from typing import Any

from colorama import Fore, Style
from colorama import init as _colorama_init

_INITIALIZED = False


def supports_color(stream: Any = None) -> bool:
    """Determine whether the output stream supports ANSI color formatting.

    Respects NO_COLOR (https://no-color.org), FORCE_COLOR, CLICOLOR_FORCE,
    and TERM=dumb.
    """
    no_color = os.environ.get("NO_COLOR")
    if no_color and no_color != "0":
        return False
    force_color = os.environ.get("FORCE_COLOR")
    if force_color and force_color != "0":
        return True
    clicolor_force = os.environ.get("CLICOLOR_FORCE")
    if clicolor_force and clicolor_force != "0":
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    target = stream if stream is not None else sys.stdout
    return hasattr(target, "isatty") and bool(target.isatty())


def init_terminal(stream: Any = None) -> None:
    """Initialize terminal color handling once at process boundary."""
    global _INITIALIZED
    if _INITIALIZED:
        return
    strip = not supports_color(stream)
    _colorama_init(autoreset=True, strip=strip, wrap=True)
    _INITIALIZED = True


# Standard Color Constants
GREEN = Fore.GREEN + Style.BRIGHT
RED = Fore.RED + Style.BRIGHT
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
GREY = Fore.BLACK + Style.BRIGHT
RESET = Style.RESET_ALL
BRIGHT = Style.BRIGHT


class C:
    """Namespace for colors and styles."""

    GREEN = GREEN
    RED = RED
    YELLOW = YELLOW
    CYAN = CYAN
    GREY = GREY
    RESET = RESET
    BRIGHT = BRIGHT


def eprint(*args: Any, **kwargs: Any) -> None:
    """Print to sys.stderr with colorama support."""
    kwargs.setdefault("file", sys.stderr)
    print(*args, **kwargs)


def error(msg: str, *, prefix: bool = True) -> None:
    """Print error message to sys.stderr."""
    tag = f"{RED}ERROR:{RESET} " if prefix else ""
    eprint(f"{tag}{msg}")


def warn(msg: str, *, prefix: bool = True) -> None:
    """Print warning message to sys.stderr."""
    tag = f"{YELLOW}WARNING:{RESET} " if prefix else ""
    eprint(f"{tag}{msg}")


def heading(msg: str) -> None:
    """Print styled section heading to sys.stdout."""
    print(f"\n{CYAN}=== {msg} ==={RESET}")


def status_tag(success: bool, *, throttled: bool = False) -> str:
    """Return colored status string for probe results."""
    if throttled:
        return f"{YELLOW}THROTTLED{RESET}"
    if success:
        return f"{GREEN}OK{RESET}"
    return f"{RED}FAIL{RESET}"
