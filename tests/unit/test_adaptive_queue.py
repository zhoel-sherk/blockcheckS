"""Unit tests for adaptive_queue (Phase 12 AQ)."""

from __future__ import annotations

import pytest

from blockchecks.engine.adaptive_queue import (
    CLUSTER_DISCORD,
    CLUSTER_YOUTUBE,
    AdaptiveJob,
    AdaptiveJobQueue,
    ScanWeights,
    cluster_domain,
    sibling_domains,
)
from blockchecks.engine.generators.base import StrategyItem

pytestmark = pytest.mark.unit


def test_cluster_domain_aq3():
    assert cluster_domain("discord.com") == CLUSTER_DISCORD
    assert cluster_domain("discord.gg") == CLUSTER_DISCORD
    assert cluster_domain("rr3---sn-foo.googlevideo.com") == CLUSTER_YOUTUBE
    assert cluster_domain("example.org") == "general"


def test_sibling_domains_aq2():
    domains = ["discord.com", "discord.gg", "google.com", "youtube.com"]
    sibs = sibling_domains("discord.com", domains)
    assert "discord.gg" in sibs
    assert "google.com" not in sibs


def test_adaptive_queue_priority_boost_aq1_aq4():
    item_a = StrategyItem(label="std_fake_stun", strategy="fake:blob=stun:repeats=6")
    item_b = StrategyItem(label="std_oob_urp", strategy="oob:urp=b")
    q = AdaptiveJobQueue.build([item_a, item_b], ["discord.com"], epsilon=0.0, seed=1)
    job = q.pop()
    assert job is not None
    q.mark_done(job, passed=True)
    # fake family boosted — second pop should prefer fake if re-enqueued
    assert q.weights.family.get("fake", 1.0) > 1.0


def test_fanout_on_pass_aq2():
    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    domains = ["discord.com", "discord.gg", "google.com"]
    q = AdaptiveJobQueue(epsilon=0.0)
    q._all_domains = domains
    q.enqueue(AdaptiveJob.from_item(item, "discord.com"))
    job = q.pop()
    added = q.mark_done(job, passed=True)
    assert added == 1
    assert "discord.gg" in q.pending_domains_for_strategy("s1")


def test_epsilon_random_explores():
    items = [StrategyItem(label=f"s{i}", strategy=f"fake:blob=stun:repeats={i}") for i in range(5)]
    q = AdaptiveJobQueue.build(items, ["d.com"], epsilon=1.0, seed=42)
    seen = {q.pop().item.label for _ in range(5)}
    assert len(seen) == 5


@pytest.mark.asyncio
async def test_scan_weights_db_roundtrip(temp_db):

    w = ScanWeights()
    w.boost_pass("fake", ["stun"], CLUSTER_DISCORD)
    await temp_db.save_scan_weights(w.to_rows())
    rows = await temp_db.load_scan_weights()
    loaded = ScanWeights.from_rows(rows)
    assert loaded.family.get("fake", 0) > 1.0
    assert loaded.blob.get("stun", 0) > 0
