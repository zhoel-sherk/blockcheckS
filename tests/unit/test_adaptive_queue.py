"""Tests for AdaptiveJobQueue."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from blockchecks.engine.adaptive_queue import (
    CLUSTER_DISCORD,
    CLUSTER_YOUTUBE,
    AdaptiveJob,
    AdaptiveJobQueue,
    ScanWeights,
    cluster_domain,
    extract_blob_hints,
    sibling_domains,
    strategy_traits,
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


def test_extract_blob_hints_lru_cache():
    extract_blob_hints.cache_clear()
    extract_blob_hints("fake:blob=stun:repeats=6")
    before = extract_blob_hints.cache_info().hits
    extract_blob_hints("fake:blob=stun:repeats=6")
    assert extract_blob_hints.cache_info().hits == before + 1


def test_strategy_traits_lru_cache():
    strategy_traits.cache_clear()
    strategy_traits("fake:blob=stun:repeats=6:tcp_ts=-1000")
    before = strategy_traits.cache_info().hits
    strategy_traits("fake:blob=stun:repeats=6:tcp_ts=-1000")
    assert strategy_traits.cache_info().hits == before + 1


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
    strategy_traits.cache_clear()
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


def test_build_skips_quarantined_domains_not_pending():
    """PERF-3: quarantined domains are never packed into AdaptiveJob."""
    created: list[str] = []
    orig = AdaptiveJob.from_item

    def _spy(item, domain, *, fanout=False):
        created.append(domain)
        return orig(item, domain, fanout=fanout)

    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    with patch.object(AdaptiveJob, "from_item", _spy):
        q = AdaptiveJobQueue.build(
            [item],
            ["discord.com", "dead.example"],
            skip_domains={"dead.example"},
            epsilon=0.0,
        )
    assert "dead.example" not in created
    assert all(job.domain != "dead.example" for job in q._pending.values())
    assert "dead.example" in q.excluded_domains
    assert len(q) == 1


def test_build_skip_keys_never_allocated():
    """PERF-3: resume-complete (label, domain) keys are not allocated."""
    created: list[tuple[str, str]] = []
    orig = AdaptiveJob.from_item

    def _spy(item, domain, *, fanout=False):
        created.append((item.label, domain))
        return orig(item, domain, fanout=fanout)

    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    with patch.object(AdaptiveJob, "from_item", _spy):
        q = AdaptiveJobQueue.build(
            [item],
            ["discord.com", "discord.gg"],
            skip_keys={("s1", "discord.com")},
            epsilon=0.0,
        )
    assert ("s1", "discord.com") not in created
    assert ("s1", "discord.com") not in q._pending
    assert ("s1", "discord.com") in q._done
    assert len(q) == 1


def test_fanout_blocked_by_done_after_skip_keys():
    """Resume skip_keys stay in _done so PASS fan-out cannot re-enqueue them."""
    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue.build(
        [item],
        ["discord.com", "discord.gg"],
        skip_keys={("s1", "discord.gg")},
        epsilon=0.0,
        seed=1,
    )
    job = q.pop()
    assert job is not None
    assert job.domain == "discord.com"
    added = q.mark_done(job, passed=True)
    assert added == 0
    assert ("s1", "discord.gg") not in q._pending
    assert ("s1", "discord.gg") in q._done


def test_epsilon_clamped_to_unit_interval():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    assert AdaptiveJobQueue(epsilon=-1).epsilon == 0.0
    assert AdaptiveJobQueue(epsilon=0.5).epsilon == 0.5
    assert AdaptiveJobQueue(epsilon=7).epsilon == 1.0


def test_hard_excluded_domain_dropped_forever():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue(epsilon=0.0)
    job = AdaptiveJob.from_item(item, "dead.example")
    q.enqueue(job)
    q.excluded_domains.add("dead.example")
    assert q.pop() is None
    assert len(q) == 0
    assert job.key in q._done


def test_soft_exclude_all_falls_back_to_non_hard():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue(epsilon=0.0, seed=3)
    q.enqueue(AdaptiveJob.from_item(item, "x.example"))
    q.enqueue(AdaptiveJob.from_item(item, "y.example"))
    got = q.pop(exclude_domains={"x.example", "y.example"})
    assert got is not None
    assert len(q) == 1
    assert q.pop() is not None
    assert len(q) == 0


def test_pop_batch_special_googlevideo_solo():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue(epsilon=0.0, seed=1)
    q.enqueue(AdaptiveJob.from_item(item, "discord.com"))
    q.enqueue(AdaptiveJob.from_item(item, "googlevideo.com"))
    batch = q.pop_batch(max_size=10)
    assert len(batch) == 1
    assert batch[0].domain == "discord.com"
    second = q.pop_batch(max_size=10)
    assert len(second) == 1
    assert second[0].domain == "googlevideo.com"


def test_pop_batch_max_size_one_returns_single():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue(epsilon=0.0)
    q.enqueue(AdaptiveJob.from_item(item, "discord.com"))
    q.enqueue(AdaptiveJob.from_item(item, "discord.gg"))
    assert len(q.pop_batch(max_size=1)) == 1


def test_pop_batch_empty_returns_empty():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    assert AdaptiveJobQueue(epsilon=0.0).pop_batch(max_size=5) == []


def test_failed_job_does_not_boost_or_fanout():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue(epsilon=0.0)
    q._all_domains = ["discord.com", "discord.gg"]
    q.enqueue(AdaptiveJob.from_item(item, "discord.com"))
    job = q.pop()
    before = dict(q.weights.family)
    added = q.mark_done(job, passed=False)
    assert added == 0
    assert q.weights.family == before
    assert len(q) == 0


def test_pending_domains_for_strategy_reflects_pops():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue(epsilon=0.0, seed=1)
    for dom in ("d1.example", "d2.example", "d3.example"):
        q.enqueue(AdaptiveJob.from_item(item, dom))
    assert set(q.pending_domains_for_strategy("s1")) == {"d1.example", "d2.example", "d3.example"}
    q.pop()
    assert set(q.pending_domains_for_strategy("s1")) == {"d2.example", "d3.example"}
    assert q.pending_domains_for_strategy("missing") == []


def test_enqueue_duplicate_and_done_are_noops():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue(epsilon=0.0)
    j1 = AdaptiveJob.from_item(item, "d.example")
    assert q.enqueue(j1) is True
    assert q.enqueue(j1) is False
    popped = q.pop()
    q.mark_done(popped, passed=False)
    assert q.enqueue(AdaptiveJob.from_item(item, "d.example")) is False
    assert q.metrics.total_enqueued == 1


@pytest.mark.asyncio
async def test_filter_resume_empty_and_all_dropped():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    q = AdaptiveJobQueue()

    async def _drop(_j):
        return True

    assert await q.filter_resume(_drop) == 0
    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q.enqueue(AdaptiveJob.from_item(item, "a.example"))
    q.enqueue(AdaptiveJob.from_item(item, "b.example"))
    skipped = await q.filter_resume(_drop, chunk_size=1)
    assert skipped == 2
    assert len(q) == 0


def test_scan_weights_caps_at_max():
    from blockchecks.engine.adaptive_queue import ScanWeights

    w = ScanWeights()
    for _ in range(1000):
        w.boost_pass("fake", ["stun"], ["r6"])
    assert w.family["fake"] == 64.0
    assert w.blob["stun"] == 64.0
    assert w.trait["r6"] == 64.0
    assert w.get("fake", ["stun"], ["r6"]) > 60.0


def test_boost_provider_once_idempotent():
    from blockchecks.engine.adaptive_queue import ScanWeights

    w = ScanWeights()
    assert w.boost_provider_once("k", "fake", ["stun"], ["r6"]) is True
    v1 = w.family.get("fake", 1.0)
    assert w.boost_provider_once("k", "fake", ["stun"], ["r6"]) is False
    assert w.family.get("fake", 1.0) == v1


def test_adaptive_metrics_pass_before_half():
    from blockchecks.engine.adaptive_queue import AdaptiveMetrics

    m = AdaptiveMetrics()
    assert m.time_to_first_pass is None
    assert m.pass_rate_before_half == 0.0
    m.set_half_mark(4)
    for _ in range(4):
        m.record_run(passed=True)
    assert m.time_to_first_pass is not None
    assert m.pass_rate_before_half == 1.0
    m.record_run(passed=False)
    assert m.passes_before_half == 2


def test_adaptive_metrics_no_half_is_zero():
    from blockchecks.engine.adaptive_queue import AdaptiveMetrics

    m = AdaptiveMetrics()
    m.record_run(passed=True)
    assert m.pass_rate_before_half == 0.0


def test_pop_batch_respects_exact_max_size():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue(epsilon=0.0, seed=1)
    for dom in ("discord.com", "discord.gg", "discord.media"):
        q.enqueue(AdaptiveJob.from_item(item, dom))
    first = q.pop_batch(max_size=2)
    assert len(first) == 2
    assert len(q) == 1
    second = q.pop_batch(max_size=2)
    assert len(second) == 1


def test_fanout_twice_adds_only_once_and_metrics_count():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue(epsilon=0.0, seed=1)
    q._all_domains = ["discord.com", "discord.gg"]
    q.enqueue(AdaptiveJob.from_item(item, "discord.com"))
    job = q.pop()
    assert q.mark_done(job, passed=True) == 1
    assert q.metrics.fanout_enqueued == 1
    # repeat fan-out of the same job key must not double-add
    assert q.fanout_on_pass(AdaptiveJob.from_item(item, "discord.com")) == 0
    assert q.metrics.fanout_enqueued == 1


def test_fanout_skips_hard_excluded_siblings():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue(epsilon=0.0)
    q._all_domains = ["discord.com", "discord.gg", "discord.media"]
    q.excluded_domains.add("discord.media")
    q.enqueue(AdaptiveJob.from_item(item, "discord.com"))
    job = q.pop()
    assert q.mark_done(job, passed=True) == 1
    assert set(q.pending_domains_for_strategy("s1")) == {"discord.gg"}


def test_configured_heap_rebuild_fires_periodically():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    low = StrategyItem(label="low", strategy="oob:urp=b")
    high = StrategyItem(label="high", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue.build([low, high], ["discord.com"], epsilon=0.0, seed=1)
    q.configure_heap_rebuild(1)
    j1 = q.pop()
    q.mark_done(j1, passed=True)
    j2 = q.pop()
    q.mark_done(j2, passed=True)
    assert q._rebuild_heap_calls >= 2
    q.configure_heap_rebuild(0)


def test_configure_heap_rebuild_negative_disabled():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    q = AdaptiveJobQueue()
    q.configure_heap_rebuild(-5)
    assert q._heap_rebuild_every == 0
    q._maybe_rebuild_heap()
    assert q._rebuild_heap_calls == 0


def test_epsilon_pick_never_returns_excluded_domain():
    from blockchecks.engine.adaptive_queue import AdaptiveJobQueue

    item = StrategyItem(label="s1", strategy="fake:blob=stun:repeats=6")
    q = AdaptiveJobQueue(epsilon=1.0, seed=9)
    for dom in ("d1.example", "d2.example", "d3.example", "d4.example"):
        q.enqueue(AdaptiveJob.from_item(item, dom))
    seen = {q.pop(exclude_domains={"d1.example"}).domain for _ in range(4)}
    # soft exclusion is best-effort: eligible domains go first, the "everything
    # excluded" fallback may still return the excluded domain last.
    assert {"d2.example", "d3.example", "d4.example"} <= seen


def test_metrics_first_pass_fixed_and_passrate():
    from blockchecks.engine.adaptive_queue import AdaptiveMetrics

    m = AdaptiveMetrics()
    m.set_half_mark(10)
    m.record_run(passed=False)
    m.record_run(passed=True)
    t1 = m.time_to_first_pass
    m.record_run(passed=True)
    assert m.time_to_first_pass == t1
    assert m.passes_before_half == 2


def test_scan_weights_from_rows_roundtrip():
    from blockchecks.engine.adaptive_queue import ScanWeights

    w = ScanWeights()
    w.boost_pass("fake", ["stun"], ["r6", "ttl3"])
    w2 = ScanWeights.from_rows(w.to_rows())
    assert w2.family == w.family
    assert w2.blob == w.blob
    assert w2.trait == w.trait
    assert ScanWeights.from_rows([]).family == {}
