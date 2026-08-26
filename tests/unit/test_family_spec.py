"""FamilySpec registry is the expander-identity source of truth."""

from __future__ import annotations

import pytest

from blockchecks.engine.family_axes import FAMILY_AXES
from blockchecks.engine.family_needs import LABEL_PREFIXES, classify_strategy_family
from blockchecks.engine.family_spec import (
    BY_NAME,
    DEFAULT_FAMILIES,
    REGISTRY,
    TCP_FAMILIES,
    TRIAGE_TO_FAMILIES,
    axes_for,
)
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.generators.standard import TCP_FAMILIES as STD_TCP_FAMILIES
from blockchecks.engine.generators.standard import StandardGenerator

pytestmark = pytest.mark.unit

# Documented extras: none today. HTTP/UDP/QUIC families have empty prefixes.
_LABEL_PREFIX_EXTRAS: frozenset[str] = frozenset()


def test_expander_identity_tables_align() -> None:
    names = {s.name for s in REGISTRY}
    assert set(StandardGenerator.STRATEGY_FAMILIES) == set(StandardGenerator._FAMILY_EXPANDERS)
    assert set(StandardGenerator._FAMILY_EXPANDERS) == names
    assert names == set(BY_NAME)
    assert names == set(FAMILY_AXES)


def test_family_axes_wired_on_specs() -> None:
    for spec in REGISTRY:
        assert spec.axes is FAMILY_AXES[spec.name]
        assert spec.axes
        assert axes_for(spec.name) is spec.axes
        assert StandardGenerator.STRATEGY_FAMILIES[spec.name] is spec.axes
    assert axes_for("not_a_family") == {}


def test_every_expander_exists_on_standard_generator() -> None:
    gen = StandardGenerator(strategy_types=["all"])
    for spec in REGISTRY:
        method = getattr(gen, spec.expander, None)
        assert callable(method), f"{spec.name} -> {spec.expander} missing"


def test_label_prefixes_keys_subset_tcp_families() -> None:
    extras = set(LABEL_PREFIXES) - set(TCP_FAMILIES)
    assert extras <= _LABEL_PREFIX_EXTRAS, f"undocumented LABEL_PREFIXES extras: {sorted(extras)}"


def test_tcp_families_order_preserved() -> None:
    assert TCP_FAMILIES == [
        "fake",
        "rst_fake",
        "synack",
        "geneva_fool",
        "wssize",
        "hostfake",
        "multisplit",
        "multidisorder",
        "syndata",
        "tcpseg",
        "oob",
        "multi_fake",
        "triple_fake",
        "fake_multisplit",
        "fake_multidisorder",
        "fake_multisplit_hostfake",
        "fake_hostfake",
        "fakedsplit",
        "fakeddisorder",
        "fake_fakedsplit",
        "tcp_ipfrag",
    ]
    assert STD_TCP_FAMILIES is TCP_FAMILIES


def test_default_tcp_and_triage_tags_match_tables() -> None:
    assert DEFAULT_FAMILIES == ("fake", "hostfake", "fakedsplit", "multisplit")
    assert {s.name for s in REGISTRY if s.default_tcp} == set(DEFAULT_FAMILIES)
    for tag, fams in TRIAGE_TO_FAMILIES.items():
        tagged = {s.name for s in REGISTRY if tag in s.triage_tags}
        assert tagged == set(fams)


def test_triple_fake_label_prefix() -> None:
    assert LABEL_PREFIXES["triple_fake"] == ("std_triple_",)
    item = StrategyItem(
        "std_triple_stun+max_ru+google_r6_tcp_ts=-1000",
        "fake:blob=stun",
    )
    assert classify_strategy_family(item) == "triple_fake"
