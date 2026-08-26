"""Unit tests for engine.resume_triage."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from blockchecks.engine.resume_triage import resume_generate_triage

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_not_resume_returns_triage():
    args = MagicMock(resume=False, triage={"stall": True})
    assert await resume_generate_triage(args, MagicMock()) == {"stall": True}


@pytest.mark.asyncio
async def test_resume_no_db_returns_triage():
    args = MagicMock(resume=True, triage="profile")
    assert await resume_generate_triage(args, None) == "profile"


@pytest.mark.asyncio
async def test_resume_with_checkpoint_returns_none():
    db = MagicMock()
    db.latest_checkpoint = AsyncMock(return_value={"step": 1})
    args = MagicMock(resume=True, triage="profile")
    assert await resume_generate_triage(args, db) is None


@pytest.mark.asyncio
async def test_resume_prefers_skip_tcp_keys():
    db = MagicMock()
    db.latest_checkpoint = AsyncMock(return_value=None)
    db.get_resume_skip_tcp_keys = AsyncMock(return_value={("s1", "youtube.com")})
    db.get_completed_tcp_keys = AsyncMock(return_value=set())
    args = MagicMock(resume=True, triage="profile")
    assert await resume_generate_triage(args, db) is None
    db.get_completed_tcp_keys.assert_not_awaited()


@pytest.mark.asyncio
async def test_resume_fallback_completed_tcp_keys():
    db = MagicMock(spec=["latest_checkpoint", "get_completed_tcp_keys"])
    db.latest_checkpoint = AsyncMock(return_value=None)
    db.get_completed_tcp_keys = AsyncMock(return_value={("s1", "youtube.com")})
    args = MagicMock(resume=True, triage="profile")
    assert await resume_generate_triage(args, db) is None


@pytest.mark.asyncio
async def test_resume_empty_keys_returns_triage():
    db = MagicMock()
    db.latest_checkpoint = AsyncMock(return_value=None)
    db.get_resume_skip_tcp_keys = AsyncMock(return_value=set())
    args = MagicMock(resume=True, triage="profile")
    assert await resume_generate_triage(args, db) == "profile"
