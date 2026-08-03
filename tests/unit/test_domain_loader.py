"""Unit tests for Phase 11 A1 domain denylist loader."""

from pathlib import Path

import pytest

from blockchecks.engine.domain_loader import (
    DenylistEntry,
    apply_denylist,
    format_skip_summary,
    load_domains,
    read_domain_lines,
    warn_zero_pass_domains,
)
from blockchecks.engine.store import StateDB


def test_read_domain_lines_strips_comments(tmp_path: Path):
    p = tmp_path / "dom.txt"
    p.write_text("# header\nyoutube.com\n# tail\n  discord.com  # inline\n")
    assert read_domain_lines(str(p)) == ["youtube.com", "discord.com"]


def test_apply_denylist_filters_exact_match():
    deny = [
        DenylistEntry("googlevideo.com", "videoplayback apex"),
        DenylistEntry("i.ytimg.com", "static CDN"),
    ]
    kept, skipped = apply_denylist(
        ["youtube.com", "googlevideo.com", "i.ytimg.com", "discord.com"],
        denylist=deny,
    )
    assert kept == ["youtube.com", "discord.com"]
    assert len(skipped) == 2
    assert skipped[0].domain == "googlevideo.com"


def test_apply_denylist_allow_unsafe():
    deny = [DenylistEntry("googlevideo.com", "")]
    kept, skipped = apply_denylist(["googlevideo.com"], denylist=deny, allow_unsafe=True)
    assert kept == ["googlevideo.com"]
    assert skipped == []


def test_load_domains_from_project_denylist():
    from blockchecks.engine.domain_loader import FULL_COVERAGE_FILE

    result = load_domains(FULL_COVERAGE_FILE, allow_unsafe=False)
    assert "youtube.com" in result.domains
    assert "googlevideo.com" in result.domains  # GV-4: videoplayback probe, not denylisted
    assert "i.ytimg.com" not in result.domains
    assert result.skipped
    assert not any(s.domain == "googlevideo.com" for s in result.skipped)


def test_coverage_tcp_lean_default():
    from blockchecks.engine.domain_loader import DEFAULT_DOMAINS_FILE

    result = load_domains(DEFAULT_DOMAINS_FILE)
    assert 11 <= len(result.domains) <= 17
    assert "youtubei.googleapis.com" in result.domains
    assert "googlevideo.com" in result.domains  # GV-4 lean coverage
    assert not result.skipped


def test_format_skip_summary():
    skipped = [
        DenylistEntry("googlevideo.com", "videoplayback apex"),
        DenylistEntry("discord.media", "voice CDN"),
    ]
    text = format_skip_summary(skipped)
    assert text.startswith("skipped 2:")
    assert "googlevideo.com (videoplayback apex)" in text


@pytest.mark.asyncio
async def test_domain_pass_stats_and_zero_warn(tmp_path: Path):
    db = StateDB(str(tmp_path / "t.db"))
    await db.init()
    for i in range(5):
        await db.log_tcp(f"s{i}", "dead.example", "FAIL", 0, 0, config_path="fake:blob=stun")
    zero = await warn_zero_pass_domains(db, ["dead.example"], min_results=5)
    assert zero == ["dead.example"]
    await db.log_tcp("s0", "dead.example", "PASS", 100, 200, config_path="fake:blob=stun")
    stats = await db.domain_pass_stats("dead.example", protos=("tcp",))
    assert stats["total"] == 5  # latest row per strategy
    assert stats["passed"] == 1
    zero2 = await warn_zero_pass_domains(db, ["dead.example"], min_results=5)
    assert zero2 == []


@pytest.mark.asyncio
async def test_count_tcp_passes_latest_row(tmp_path: Path):
    """Historical PASS must not inflate count after a later FAIL on same strategy."""
    db = StateDB(str(tmp_path / "t.db"))
    await db.init()
    await db.log_tcp("s1", "discord.com", "PASS", 100, 200, config_path="fake:blob=stun")
    assert await db.count_tcp_passes("discord.com") == 1
    await db.log_tcp("s1", "discord.com", "FAIL", 0, 0, config_path="fake:blob=stun")
    assert await db.count_tcp_passes("discord.com") == 0
    assert await db.count_tcp_passes() == 0
