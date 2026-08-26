"""Backward-compat re-export; implementation in engine.composite_runner."""

from blockchecks.engine.composite_runner import (
    DOMAINS,
    normalize_domains,
    run,
)
from blockchecks.engine.composite_runner import _valid_domain  # noqa: F401 — tests

__all__ = ["DOMAINS", "normalize_domains", "run", "_valid_domain"]
