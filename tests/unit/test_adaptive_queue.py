"""Tests for AdaptiveJobQueue."""

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
    fam = job.family
    assert fam  # classified
    q.mark_done(job, passed=True)
    assert q.weights.family.get(fam, 1.0) > 1.0

    # Fresh queue with pre-boosted weights: boosted family must pop first (ε=0)
    w = ScanWeights()
    w.family[fam] = 5.0
    q2 = AdaptiveJobQueue.build([item_a, item_b], ["discord.com"], weights=w, epsilon=0.0, seed=1)
    nxt = q2.pop()
    assert nxt is not None
    assert nxt.family == fam


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


def test_epsilon_pop_returns_pending_job():
    """ε=1.0 must still return a pending job without building eligible lists (PERF-4)."""
    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue.build([item], ["discord.com", "discord.gg"], epsilon=1.0, seed=7)
    job = q.pop()
    assert job is not None
    assert job.domain in {"discord.com", "discord.gg"}


def test_pop_batch_skips_full_heap_rebuild(monkeypatch):
    """pop_batch must not O(n)-rebuild heap after every multi-domain batch (PERF-2)."""
    items = [StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")]
    domains = ["discord.com", "discord.gg", "discord.media"]
    q = AdaptiveJobQueue.build(items, domains, epsilon=0.0, seed=1)
    rebuild_calls = 0
    orig = q._rebuild_heap

    def spy_rebuild() -> None:
        nonlocal rebuild_calls
        rebuild_calls += 1
        orig()

    monkeypatch.setattr(q, "_rebuild_heap", spy_rebuild)
    batch = q.pop_batch(max_size=3)
    assert len(batch) >= 2
    assert rebuild_calls == 0
    q.mark_done(batch[0], passed=True)
    assert rebuild_calls == 0


def test_cluster_domain_lru_cache():
    cluster_domain.cache_clear()
    cluster_domain("discord.com")
    before = cluster_domain.cache_info().hits
    cluster_domain("discord.com")
    assert cluster_domain.cache_info().hits == before + 1


@pytest.mark.asyncio
async def test_scan_weights_db_roundtrip(temp_db):

    w = ScanWeights()
    w.boost_pass("fake", ["stun"], ["r6"])
    await temp_db.save_scan_weights(w.to_rows())
    rows = await temp_db.load_scan_weights()
    loaded = ScanWeights.from_rows(rows)
    assert loaded.family.get("fake", 0) > 1.0
    assert loaded.blob.get("stun", 0) > 0


def test_strategy_traits_extracts_axes():
    from blockchecks.engine.adaptive_queue import strategy_traits

    tr = strategy_traits("fake:blob=stun:repeats=6:tcp_ts=-1000:ip_ttl=127")
    assert "r6" in tr
    assert "fool:tcp_ts" in tr
    assert "ttl3" in tr  # 127 → bucket 3

    tr2 = strategy_traits("multisplit:pos=1,midsld:seqovl=68")
    assert "pos:1,midsld" in tr2


def test_pop_exclude_domains_isolates():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue
    from blockchecks.engine.generators.base import StrategyItem

    domains = ["youtube.com", "discord.com", "aws.com"]
    q = AdaptiveJobQueue.build(
        [StrategyItem("s1", "fake:blob=stun:repeats=6")],
        domains,
        epsilon=0.0,
        seed=1,
    )
    # first pop is youtube
    first = q.pop()
    assert first.domain == "youtube.com"
    # exclude youtube → another domain
    second = q.pop(exclude_domains={"youtube.com"})
    assert second is not None
    assert second.domain != "youtube.com"
    # exclude both busy domains → any leftover, or None if all are busy
    third = q.pop(exclude_domains={"youtube.com", second.domain})
    assert third is None or third.domain in domains


def test_scan_weights_has_no_cluster_boost():
    from blockchecks.engine.adaptive_queue import ScanWeights

    w = ScanWeights()
    assert not hasattr(w, "cluster")
    w.boost_pass("fake", ["stun"], ["r6"])
    assert w.family.get("fake") > 1.0
    assert w.blob.get("stun") > 0
    assert w.trait.get("r6") > 0


def test_scan_weights_seed_from_triage():
    from blockchecks.engine.triage import TriageProfile

    w = ScanWeights()
    w.seed_from_triage(
        TriageProfile(
            silent_drop_after_sni=True,
            viable_foolings=["tcp_ts=-1000"],
            viable_blobs=["stun"],
        )
    )
    assert w.family.get("fake", 1.0) >= 2.0
    assert "fool:badsum" not in w.trait
    assert w.trait.get("fool:tcp_ts", 0) > 0
    assert w.blob.get("stun", 0) > 0
    w.seed_from_triage(TriageProfile(dead_foolings=["badsum"]))
    assert w.trait.get("fool:badsum") == 0.1


def test_scan_weights_seed_from_triage_idempotent_on_resume():
    """Persisted weights must not double on repeated seed_from_triage (ENG-3)."""
    from blockchecks.engine.triage import TriageProfile

    w = ScanWeights()
    w.family["fake"] = 5.0
    profile = TriageProfile(
        silent_drop_after_sni=True,
        viable_foolings=["tcp_ts=-1000"],
        viable_blobs=["stun"],
    )
    w.seed_from_triage(profile)
    assert w.family["fake"] == 5.0
    w.seed_from_triage(profile)
    assert w.family["fake"] == 5.0
    assert w.trait.get("fool:tcp_ts", 0) <= 64.0


def test_mark_done_rebuilds_heap_after_boost():
    """Bridge mode: boost_pass must affect subsequent pop() ordering (ENG-3)."""
    low = StrategyItem(label="low", strategy="oob:urp=b")
    high = StrategyItem(label="high", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue.build([low, high], ["discord.com"], epsilon=0.0, seed=1)
    q.configure_heap_rebuild(1)
    first = q.pop()
    assert first is not None
    q.mark_done(first, passed=True)
    second = q.pop()
    assert second is not None
    assert second.item.label == "high"


def test_scan_weights_seed_pos_and_blob_aliases():
    from blockchecks.engine.triage import TriageProfile

    w = ScanWeights()
    w.seed_from_triage(
        TriageProfile(
            viable_blobs=["tls_clienthello"],
            split_mode="sni_marker",
        )
    )
    assert w.trait.get("pos:sniext+1", 0) > 0
    assert w.blob.get("google", 0) > 0
    assert w.blob.get("tls_clienthello", 0) > 0
    w2 = ScanWeights()
    w2.seed_from_triage(TriageProfile(split_mode="first_byte"))
    assert w2.trait.get("pos:1", 0) > 0
    w3 = ScanWeights()
    w3.seed_from_triage(TriageProfile(split_mode="seqovl"))
    assert w3.trait.get("fool:seqovl", 0) > 0


@pytest.mark.asyncio
async def test_filter_resume_pure_check():
    """filter_resume stays I/O-free — the caller supplies the check callback."""
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    q = AdaptiveJobQueue()
    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q.enqueue(AdaptiveJob.from_item(item, "discord.com"))
    q.enqueue(AdaptiveJob.from_item(item, "youtube.com"))

    # pure callback: drop discord.com only (no DB, no I/O).
    async def _check(job: AdaptiveJob) -> bool:
        return job.domain == "discord.com"

    skipped = await q.filter_resume(_check, chunk_size=1)
    assert skipped == 1
    assert len(q) == 1
    remaining = q.pop()
    assert remaining is not None
    assert remaining.domain == "youtube.com"
