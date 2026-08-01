"""BC2-6 family need_* gating unit tests."""

from __future__ import annotations

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
