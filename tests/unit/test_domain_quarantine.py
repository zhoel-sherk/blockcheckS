"""Unit tests for engine.domain_quarantine (mid-run dead-domain skip)."""

from __future__ import annotations

import pytest

from blockchecks.engine.domain_quarantine import (
    DomainQuarantine,
    QuarantineConfig,
    append_denylist,
    quarantine_from_args,
)


@pytest.mark.unit
def test_record_quarantines_after_min_failed_attempts() -> None:
    q = DomainQuarantine(QuarantineConfig(min_attempts=3))
    assert q.record("bad.example", False) is None
    assert q.record("bad.example", False) is None
    assert q.record("bad.example", True) is None  # a PASS resets the streak risk
    assert "bad.example" not in q.quarantined
    assert q.record("bad.example", False) is None  # attempts=4, but passed>0
    assert "bad.example" not in q.quarantined


@pytest.mark.unit
def test_record_zero_pass_domain_hits_threshold() -> None:
    q = DomainQuarantine(QuarantineConfig(min_attempts=3))
    q.record("dead.example", False)
    q.record("dead.example", False)
    assert q.record("dead.example", False) == "dead.example"
    assert q.exclude_domains() == {"dead.example"}
    # further probes on the quarantined domain are no-ops
    assert q.record("dead.example", False) is None
    assert q.quarantined["dead.example"]["attempts"] == 3


@pytest.mark.unit
def test_seed_from_rows_prequarantines_known_dead() -> None:
    q = DomainQuarantine(QuarantineConfig(min_attempts=300))
    newly = q.seed_from_rows(
        [
            ("url-protection.discord.com", 11674, 0),
            ("discordcdn.com", 10935, 6818),
            ("fresh.example", 5, 0),
        ]
    )
    assert newly == ["url-protection.discord.com"]
    assert "url-protection.discord.com" in q.exclude_domains()
    # recording more failures on an already-quarantined domain is a no-op
    assert q.record("url-protection.discord.com", False) is None


@pytest.mark.unit
def test_disabled_config_records_nothing() -> None:
    q = DomainQuarantine(QuarantineConfig(enabled=False, min_attempts=1))
    assert q.record("dead.example", False) is None
    assert q.seed_from_rows([("x.example", 9999, 0)]) == []
    assert q.exclude_domains() == set()


@pytest.mark.unit
def test_quarantine_from_args() -> None:
    class Args:
        no_quarantine = False
        quarantine_min = 150
        quarantine_auto_denylist = True

    cfg = quarantine_from_args(Args())
    assert cfg is not None and cfg.min_attempts == 150 and cfg.auto_denylist

    class Zero:
        no_quarantine = False
        quarantine_min = 0
        quarantine_auto_denylist = False

    z = quarantine_from_args(Zero())
    assert z is not None and z.min_attempts == 0

    class Off:
        no_quarantine = True

    assert quarantine_from_args(Off()) is None


@pytest.mark.unit
def test_record_throttled_status_counts_as_pass() -> None:
    q = DomainQuarantine(QuarantineConfig(min_attempts=3))
    assert q.record("slow.example", False, status="THROTTLED") is None
    assert q.record("slow.example", False, status="THROTTLED") is None
    assert q.record("slow.example", False, status="FAIL") is None
    assert "slow.example" not in q.quarantined
    assert q.stats["slow.example"].passed == 2


@pytest.mark.unit
@pytest.mark.asyncio
async def test_domain_pass_rows_counts_throttled_as_pass(temp_db) -> None:
    await temp_db.log_tcp("s1", "slow.example", "THROTTLED", 100.0, 206, config_path="fake:1")
    await temp_db.log_tcp("s2", "slow.example", "FAIL", 100.0, 0, config_path="fake:2")
    await temp_db.log_tcp("s3", "dead.example", "FAIL", 100.0, 0, config_path="fake:3")
    await temp_db.flush()

    by_domain = {d: (total, passed) for d, total, passed in await temp_db.domain_pass_rows()}
    assert by_domain["slow.example"] == (2, 1)
    assert by_domain["dead.example"] == (1, 0)

    q = DomainQuarantine(QuarantineConfig(min_attempts=1))
    assert q.seed_from_rows(await temp_db.domain_pass_rows()) == ["dead.example"]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_store_quarantine_roundtrip(temp_db) -> None:
    await temp_db.quarantine_domain(
        "router.discord.media", reason="0 PASS in 300 attempts", failed=300
    )
    await temp_db.quarantine_domain(
        "router.discord.media", reason="0 PASS in 500 attempts", failed=500
    )
    rows = await temp_db.get_quarantined()
    assert len(rows) == 1
    assert rows[0]["domain"] == "router.discord.media"
    assert rows[0]["failed"] == 500

    bulk = await temp_db.domain_pass_rows()
    assert isinstance(bulk, list) and all(len(r) == 3 for r in bulk)


@pytest.mark.unit
def test_append_denylist_writes_once(tmp_path) -> None:
    p = tmp_path / "denylist.txt"
    entries = [
        {"domain": "Dead.Example", "ts": "2026-08-24T21:00:00", "reason": "0 PASS in 3"},
        {"domain": "other.example", "ts": "2026-08-24T21:00:01", "reason": "0 PASS in 4"},
    ]
    written = append_denylist(entries, denylist_path=str(p))
    assert sorted(written) == ["dead.example", "other.example"]
    # second call must not duplicate
    written2 = append_denylist(entries[:1], denylist_path=str(p))
    assert written2 == []
    text = p.read_text(encoding="utf-8")
    assert text.count("dead.example") == 1
    assert "# auto-quarantine" in text
