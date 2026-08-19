"""CLI run profiles (--profile smoke|fast|20h).

Provides predefined bundles of flags for common execution scenarios
such as rapid smoke tests, interactive fast scans, or 20-hour mass campaigns.
"""

from __future__ import annotations

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


def apply_profile(args: Any) -> None:
    """Apply profile defaults to args if --profile is specified."""
    profile_name = getattr(args, "profile", None)
    if not profile_name:
        return
    profile = PROFILES.get(profile_name)
    if not profile:
        return
    for k, v in profile.items():
        setattr(args, k, v)
