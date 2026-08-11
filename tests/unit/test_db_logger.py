"""Unit tests for the deprecated db_logger re-export shim."""

from __future__ import annotations

import sys
import warnings


def _reimport():
    sys.modules.pop("blockchecks.engine.db_logger", None)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        from blockchecks.engine import db_logger  # noqa: F401
    sys.modules.pop("blockchecks.engine.db_logger", None)
    return db_logger, w


def test_db_logger_deprecation_warning_and_exports():
    dl, w = _reimport()
    assert any(issubclass(x.category, DeprecationWarning) for x in w)
    assert dl.StateDB is not None
    for name in ("Checkpoint", "SqliteRunStore", "matrix_fingerprint", "open_run_store"):
        assert hasattr(dl, name)
