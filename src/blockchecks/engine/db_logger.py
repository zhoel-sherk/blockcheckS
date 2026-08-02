"""Deprecated: use blockchecks.engine.store instead."""

from __future__ import annotations

import warnings

from blockchecks.engine.store import (
    Checkpoint,
    SqliteRunStore,
    matrix_fingerprint,
    open_run_store,
)

warnings.warn(
    "blockchecks.engine.db_logger is deprecated; use blockchecks.engine.store",
    DeprecationWarning,
    stacklevel=2,
)

StateDB = SqliteRunStore

__all__ = ["Checkpoint", "StateDB", "SqliteRunStore", "matrix_fingerprint", "open_run_store"]
