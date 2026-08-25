"""Named flag bundles: smoke, fast, 20h."""

from __future__ import annotations

import sys
from typing import Any

PROFILES: dict[str, dict[str, Any]] = {
    "smoke": {
        "max": 20,
        "scan_level": "fast",
        "parallel": 1,
        "curl_parallel": 1,
        "timeout": 2.0,
        "quick": True,
    },
    "fast": {
        "scan_level": "fast",
        "max": 100,
        "timeout": 3.0,
    },
    "20h": {
        "scan_level": "full",
        "resume": True,
        "no_preflight": True,
        "no_wssize": True,
        "timeout": 2.0,
        "allow_dns_hijack": True,
        "fan_out": True,
    },
}

_UNSET = object()

# argparse/CliApp values used when the user did not pass the flag.
# ``max`` / ``scan_level`` are mode-dependent (full vs scan/pair).
_UNSET_VALUES: dict[str, frozenset[Any]] = {
    "max": frozenset({100}),
    "scan_level": frozenset({"fast", "full"}),
    "timeout": frozenset({3.0}),
    "curl_parallel": frozenset({1}),
    "quick": frozenset({False}),
    "resume": frozenset({False}),
    "no_preflight": frozenset({False}),
    "no_wssize": frozenset({False}),
    "allow_dns_hijack": frozenset({False}),
    "fan_out": frozenset({False}),
}

_CLI_FLAGS: dict[str, tuple[str, ...]] = {
    "max": ("--max",),
    "scan_level": ("--scan-level",),
    "parallel": ("--parallel",),
    "curl_parallel": ("--curl-parallel",),
    "timeout": ("--timeout",),
    "quick": ("--quick",),
    "resume": ("--resume",),
    "no_preflight": ("--no-preflight",),
    "no_wssize": ("--no-wssize",),
    "allow_dns_hijack": ("--allow-dns-hijack",),
    "fan_out": ("--fan-out",),
}


def flags_present_in_argv(argv: list[str] | None = None) -> set[str]:
    """Dest names whose flags appear in argv (explicit CLI)."""
    tokens = argv if argv is not None else sys.argv[1:]
    return {
        dest
        for dest, flags in _CLI_FLAGS.items()
        if any(tok == flag or tok.startswith(f"{flag}=") for tok in tokens for flag in flags)
    }


def _explicit_profile_keys(args: Any) -> set[str]:
    tagged = getattr(args, "_explicit_cli", None)
    return set(tagged) if isinstance(tagged, (set, frozenset)) else set()


def _is_unset_value(key: str, current: Any) -> bool:
    if key == "parallel":
        from blockchecks.engine.config import effective_default_pool_size

        return current == effective_default_pool_size()
    if key == "curl_parallel":
        from blockchecks.engine.config import DEFAULT_CURL_PARALLEL

        return current in {DEFAULT_CURL_PARALLEL, 1}
    unset = _UNSET_VALUES.get(key)
    return unset is not None and current in unset


def apply_profile(args: Any) -> None:
    """Apply profile defaults without clobbering explicit CLI arguments."""
    profile_name = getattr(args, "profile", None)
    if not profile_name:
        return
    profile = PROFILES.get(profile_name)
    if not profile:
        return
    explicit = _explicit_profile_keys(args)
    for k, v in profile.items():
        if k in explicit:
            continue
        current = getattr(args, k, _UNSET)
        if current is _UNSET or _is_unset_value(k, current):
            setattr(args, k, v)
