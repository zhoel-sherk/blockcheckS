"""Backward-compat re-export; implementation in engine.composite_runner."""

from blockchecks.engine.composite_runner import (
    DOMAINS,
    _valid_domain,  # noqa: F401 — tests
    normalize_domains,
    run,
)

__all__ = ["DOMAINS", "normalize_domains", "run", "_valid_domain"]
