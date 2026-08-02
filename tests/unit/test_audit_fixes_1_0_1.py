"""Audit fix regressions: wall timeout, AQ GV solo, family finish, THROTTLED working."""

from __future__ import annotations

import pytest

from blockchecks.checkers.curl_probe import worker_wall_timeout
from blockchecks.engine.adaptive_queue import AdaptiveJobQueue
from blockchecks.engine.family_needs import FamilyNeedTracker, classify_strategy_family
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.store import open_run_store

pytestmark = pytest.mark.unit


def test_worker_wall_timeout_scales_with_repeats():
    t = worker_wall_timeout(5.0, repeats=5, settle_slack=15.0)
    assert t >= 5.0 * 5 + 15.0
    # parallel_repeats collapses to one wave
    tp = worker_wall_timeout(5.0, repeats=5, parallel_repeats=True, settle_slack=15.0)
    assert tp >= 5.0 + 15.0
    assert tp < t


def test_pop_batch_solos_googlevideo():
    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    domains = [
        "rr1---sn-a.googlevideo.com",
        "rr2---sn-b.googlevideo.com",
        "discord.com",
    ]
    q = AdaptiveJobQueue.build([item], domains, epsilon=0.0, seed=1)
    batch = q.pop_batch(8, protocol="tls12")
    assert len(batch) == 1
    assert "googlevideo" in batch[0].domain


def test_finish_family_fakedsplit_clears_needs():
    assert classify_strategy_family(StrategyItem("std_fds_x", "fakedsplit:pos=1")) == "fakedsplit"
    tracker = FamilyNeedTracker()
    tracker.finish_family("fakedsplit", True)
    assert tracker.need_fakedsplit == 0
    assert tracker.need_fakeddisorder == 0
    dep = StrategyItem("std_ffds_x", "fake:blob=stun\nfakedsplit:pos=1")
    assert tracker.skip_strategy(dep, "fast") is True


@pytest.mark.asyncio
async def test_throttled_counts_as_working(tmp_path):
    db = open_run_store(tmp_path / "t.db")
    await db.init()
    await db.log_tcp("s1", "discord.com", "THROTTLED", 100.0, http_code=206)
    await db.log_tcp("s2", "discord.com", "PASS", 50.0, http_code=200)
    await db.log_tcp("s3", "discord.com", "FAIL", 0.0, http_code=0)
    working = await db.get_working_tcp("discord.com")
    assert "s1" in working
    assert "s2" in working
    assert "s3" not in working
    cov = await db.coverage_score("s1")
    assert cov["domains_passed"] == 1


@pytest.mark.asyncio
async def test_completed_pair_keys(tmp_path):
    db = open_run_store(tmp_path / "p.db")
    await db.init()
    await db.log_pair("t1", "u1", "discord.com", True, False, True, 10, 0, 20, "PASS")
    await db.log_pair("t1", "u2", "discord.com", True, False, False, 10, 0, 0, "PARTIAL")
    keys = await db.get_completed_pair_keys("discord.com")
    assert ("t1", "u1") in keys
    assert ("t1", "u2") in keys


def test_netns_base_reject_shell_metachar():
    from blockchecks.engine.netns_pool import NetNsPool

    with pytest.raises(ValueError):
        NetNsPool(size=1, base="bs;rm")
