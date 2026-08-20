"""BC2-6 family need_* gating unit tests."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from blockchecks.engine.family_needs import (
    FamilyNeedTracker,
    classify_strategy_family,
    sort_by_family,
)
from blockchecks.engine.generators.base import StrategyItem

pytestmark = pytest.mark.unit


def test_classify_standard_labels():
    assert classify_strategy_family(StrategyItem("std_fake_stun_r6", "fake:blob=stun")) == "fake"
    assert (
        classify_strategy_family(StrategyItem("std_hostfake_base", "hostfakesplit:nofake2"))
        == "hostfake"
    )
    assert (
        classify_strategy_family(StrategyItem("std_fake_hostfake_x", "fake\nhostfakesplit"))
        == "fake_hostfake"
    )
    assert classify_strategy_family(StrategyItem("simple_fake_alt2", "fake:blob=stun")) == "other"


def test_sort_by_family_order():
    items = [
        StrategyItem("std_multisplit_p2", "multisplit:pos=2"),
        StrategyItem("std_fake_stun_r6", "fake:blob=stun"),
        StrategyItem("std_hostfake_base", "hostfakesplit:nofake2"),
    ]
    ordered = [i.label for i in sort_by_family(items)]
    assert ordered == ["std_fake_stun_r6", "std_hostfake_base", "std_multisplit_p2"]


def test_skip_fake_hostfake_when_hostfake_passed():
    tracker = FamilyNeedTracker(need_hostfakesplit=0)
    item = StrategyItem("std_fake_hostfake_x", "fake\nhostfakesplit")
    assert tracker.skip_family("fake_hostfake", "fast") is True
    assert tracker.skip_strategy(item, "fast") is False


def test_skip_multisplit_combo_when_multisplit_passed():
    tracker = FamilyNeedTracker(need_multisplit=0)
    item = StrategyItem("combo", "fake:blob=stun\nmultisplit:pos=2")
    assert tracker.skip_strategy(item, "fast") is True
    assert tracker.skip_strategy(item, "full") is False


def test_finish_family_updates_needs():
    tracker = FamilyNeedTracker()
    tracker.finish_family("hostfake", True)
    assert tracker.need_hostfakesplit == 0
    tracker.finish_family("multisplit", False)
    assert tracker.need_multisplit == 1


# ── run_tcp_with_family_gates (async) ─────────────────────────────────


def test_run_family_gates_single_break():
    import asyncio

    from blockchecks.engine.family_needs import run_tcp_with_family_gates

    items = [
        StrategyItem("std_fake_a", "fake:blob=stun"),
        StrategyItem("std_hostfake_b", "hostfakesplit:nofake2"),
    ]
    runner = MagicMock()
    runner.test_tcp = AsyncMock(return_value=MagicMock(success=True))
    results, done, skipped, passed = asyncio.run(
        run_tcp_with_family_gates(runner, items, "d.com", scan_level="single", timeout=3.0)
    )
    assert passed == 1
    assert results


def test_run_family_gates_skips_resumed():
    import asyncio

    from blockchecks.engine.family_needs import run_tcp_with_family_gates

    items = [StrategyItem("std_fake_a", "fake:blob=stun")]
    runner = MagicMock()

    async def _resume(label, dom):
        return True

    results, done, skipped, passed = asyncio.run(
        run_tcp_with_family_gates(
            runner, items, "d.com", scan_level="fast", timeout=3.0, resume_check=_resume
        )
    )
    assert skipped == 1 and done == 1
    runner.test_tcp.assert_not_called()


def test_run_family_gates_stop_event():
    import asyncio

    from blockchecks.engine.family_needs import run_tcp_with_family_gates

    items = [StrategyItem("std_fake_a", "fake:blob=stun")]
    runner = MagicMock()
    ev = asyncio.Event()
    ev.set()
    results, done, skipped, passed = asyncio.run(
        run_tcp_with_family_gates(
            runner, items, "d.com", scan_level="fast", timeout=3.0, stop_event=ev
        )
    )
    assert done == 0
    runner.test_tcp.assert_not_called()


def test_map_triage_to_generators_empty_profile_falls_back_standard():
    from blockchecks.engine.family_needs import map_triage_to_generators
    from blockchecks.engine.family_registry import DEFAULT_FAMILIES
    from blockchecks.engine.triage import TriageProfile

    assert map_triage_to_generators(TriageProfile()) == list(DEFAULT_FAMILIES)


def test_map_triage_to_generators_stall_phase():
    from blockchecks.engine.fail_phase import FailPhase
    from blockchecks.engine.family_needs import map_triage_to_generators
    from blockchecks.engine.triage import TriageProfile

    result = map_triage_to_generators(TriageProfile(stall_phase=FailPhase.DATA_STALL_16K))
    assert result == ["wssize"]


def test_map_triage_to_generators_rst_at_sni():
    from blockchecks.engine.family_needs import map_triage_to_generators
    from blockchecks.engine.triage import TriageProfile

    result = map_triage_to_generators(TriageProfile(rst_at_sni=True))
    assert result == ["multisplit", "fakedsplit", "multidisorder"]


def test_map_triage_to_generators_quic_drop():
    from blockchecks.engine.family_needs import map_triage_to_generators
    from blockchecks.engine.triage import TriageProfile

    result = map_triage_to_generators(TriageProfile(quic_drop=True))
    assert result == ["quic_fake", "quic_ipfrag"]


def test_map_triage_to_generators_combined_deduped():
    from blockchecks.engine.fail_phase import FailPhase
    from blockchecks.engine.family_needs import map_triage_to_generators
    from blockchecks.engine.triage import TriageProfile

    profile = TriageProfile(
        rst_at_sni=True,
        stall_phase=FailPhase.DATA_STALL_16K,
        quic_drop=True,
    )
    result = map_triage_to_generators(profile)
    assert result == [
        "wssize",
        "multisplit",
        "fakedsplit",
        "multidisorder",
        "quic_fake",
        "quic_ipfrag",
    ]
    assert len(result) == len(set(result))


def test_map_triage_to_generators_unknown_stall_ignored():
    from blockchecks.engine.fail_phase import FailPhase
    from blockchecks.engine.family_needs import map_triage_to_generators
    from blockchecks.engine.family_registry import DEFAULT_FAMILIES
    from blockchecks.engine.triage import TriageProfile

    result = map_triage_to_generators(TriageProfile(stall_phase=FailPhase.UNKNOWN))
    assert result == list(DEFAULT_FAMILIES)
