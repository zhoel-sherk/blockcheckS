"""Resume-aware triage selection for matrix generation (neutral layer; no CLI)."""

from __future__ import annotations

from typing import Any


def _resume_keys_fn(db: Any) -> Any:
    """Prefer get_resume_skip_tcp_keys; fall back to get_completed_tcp_keys."""
    if db is None:
        return None
    mock_children = getattr(db, "_mock_children", None)
    if mock_children is not None:
        if "get_resume_skip_tcp_keys" in mock_children:
            return db.get_resume_skip_tcp_keys
        if "get_completed_tcp_keys" in mock_children:
            return db.get_completed_tcp_keys
        return None
    fn = getattr(db, "get_resume_skip_tcp_keys", None)
    if callable(fn):
        return fn
    return getattr(db, "get_completed_tcp_keys", None)


async def resume_generate_triage(args: Any, db: Any) -> Any:
    """Triage prune changes the item list; resume must keep the original matrix."""
    if not getattr(args, "resume", False) or db is None:
        return getattr(args, "triage", None)
    latest = getattr(db, "latest_checkpoint", None)
    if callable(latest) and await latest():
        return None
    keys_fn = _resume_keys_fn(db)
    if callable(keys_fn) and await keys_fn():
        return None
    return getattr(args, "triage", None)
