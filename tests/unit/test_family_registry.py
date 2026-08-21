"""Family registry: triage → expander names and matrix pruning."""

from blockchecks.engine.fail_phase import FailPhase
from blockchecks.engine.family_registry import (
    DEFAULT_FAMILIES,
    dead_fooling_tokens,
    families_for_profile,
    prune_items_by_triage,
)
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.triage import TriageProfile


def test_families_empty_falls_back_to_defaults():
    assert families_for_profile(None) == list(DEFAULT_FAMILIES)
    assert families_for_profile(TriageProfile()) == list(DEFAULT_FAMILIES)


def test_families_silent_drop_and_rst():
    silent = TriageProfile(silent_drop_after_sni=True)
    assert families_for_profile(silent) == [
        "fake",
        "hostfake",
        "fakedsplit",
        "multisplit",
        "multi_fake",
    ]
    rst = TriageProfile(rst_at_sni=True)
    assert families_for_profile(rst) == ["multisplit", "fakedsplit", "multidisorder"]


def test_families_udp_blocked():
    assert families_for_profile(TriageProfile(udp_blocked=True)) == ["udp_discord"]


def test_dead_fooling_empty_until_grid_runs():
    assert dead_fooling_tokens(TriageProfile()) == ()
    dead = dead_fooling_tokens(TriageProfile(viable_foolings=["tcp_ts=-1000", "tcp_md5"]))
    assert "badsum" in dead
    assert "tcp_ts" not in dead
    assert "tcp_md5" not in dead


def test_dead_foolings_from_profile_without_grid():
    dead = dead_fooling_tokens(TriageProfile(dead_foolings=["send", "badsum"]))
    assert "send" in dead
    assert "badsum" in dead


def test_tcp_seq_viable_does_not_kill_badsid():
    dead = dead_fooling_tokens(TriageProfile(viable_foolings=["tcp_seq=1000"]))
    assert "tcp_seq" not in dead
    assert "badsid" not in dead
    assert "badsum" in dead


def test_prune_drops_dead_badsum():
    items = [
        StrategyItem(label="ok", strategy="fake:blob=stun:repeats=6:tcp_ts=-1000"),
        StrategyItem(label="dead", strategy="fake:blob=stun:repeats=6:badsum"),
        StrategyItem(label="plain", strategy="fake:blob=stun:repeats=6"),
    ]
    profile = TriageProfile(viable_foolings=["tcp_ts=-1000"])
    kept = prune_items_by_triage(items, profile)
    assert [i.label for i in kept] == ["ok"]


def test_prune_drops_ipv6_extra_without_viable_fooling():
    items = [
        StrategyItem(label="hop", strategy="fake:blob=stun:repeats=6:ip6_hopbyhop"),
        StrategyItem(
            label="hop_ts", strategy="fake:blob=stun:repeats=6:ip6_hopbyhop:tcp_ts=-1000"
        ),
    ]
    profile = TriageProfile(viable_foolings=["tcp_ts=-1000"])
    assert [i.label for i in prune_items_by_triage(items, profile)] == ["hop_ts"]


def test_prune_drops_ttl_before_dpi():
    items = [
        StrategyItem(label="low", strategy="fake:blob=stun:repeats=6:ip_ttl=1"),
        StrategyItem(label="ok", strategy="fake:blob=stun:repeats=6:ip_ttl=5"),
        StrategyItem(label="high", strategy="fake:blob=stun:repeats=6:ip_ttl=64"),
    ]
    profile = TriageProfile(dpi_hops=3, server_hops=12)
    kept = {i.label for i in prune_items_by_triage(items, profile)}
    assert kept == {"ok"}


def test_prune_unbypassable_empties():
    items = [StrategyItem(label="x", strategy="fake:blob=stun:repeats=6")]
    assert prune_items_by_triage(items, TriageProfile(unbypassable_l3=True)) == []


def test_prune_partial_blobs_drops_stun():
    items = [StrategyItem(label="stun", strategy="fake:blob=stun:repeats=6:tcp_ts=-1000")]
    profile = TriageProfile(viable_foolings=["tcp_ts=-1000"], viable_blobs=["tls_clienthello"])
    assert prune_items_by_triage(items, profile) == []


def test_filter_fooling_values_drops_badsum():
    from blockchecks.engine.family_registry import filter_fooling_values

    profile = TriageProfile(viable_foolings=["tcp_ts=-1000", "tcp_md5"])
    kept = filter_fooling_values(["tcp_ts=-1000", "badsum", "tcp_md5", ""], profile)
    assert "badsum" not in kept
    assert "tcp_ts=-1000" in kept
    assert "" in kept


def test_filter_ttl_values_keeps_autottl_and_window():
    from blockchecks.engine.family_registry import filter_ttl_values

    profile = TriageProfile(dpi_hops=3, server_hops=12)
    kept = filter_ttl_values([1, 5, 64, "-1,3-20"], profile)
    assert 1 not in kept
    assert 64 not in kept
    assert 5 in kept
    assert "-1,3-20" in kept


def test_filter_split_positions_by_mode():
    from blockchecks.engine.family_registry import filter_split_positions

    first = filter_split_positions(
        ["1", "sniext+1", "midsld"], TriageProfile(split_mode="first_byte")
    )
    assert "sniext+1" not in first
    assert "1" in first
    marker = filter_split_positions(
        ["1", "1,midsld", "sniext+1"], TriageProfile(split_mode="sni_marker")
    )
    assert "1" not in marker
    assert "sniext+1" in marker


def test_prune_drops_nonviable_blob_class():
    items = [
        StrategyItem(label="stun", strategy="fake:blob=stun:repeats=6"),
        StrategyItem(label="quic", strategy="fake:blob=quic_google:repeats=6"),
    ]
    profile = TriageProfile(viable_blobs=["stun"])
    kept = prune_items_by_triage(items, profile)
    assert [i.label for i in kept] == ["stun"]


def test_prune_stall_does_not_change_items_without_fooling_grid():
    items = [StrategyItem(label="x", strategy="fake:blob=stun:repeats=6:badsum")]
    profile = TriageProfile(stall_phase=FailPhase.DATA_STALL_16K)
    assert prune_items_by_triage(items, profile) == items
