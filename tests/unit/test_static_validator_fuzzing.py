"""Hypothesis fuzzing for engine.static_validator and strategy parsers.

Guarantees validate_strategy / split_cli_args / escape_conf_lt / strategy_traits
never raise on arbitrary (incl. hostile) input, and that all real preset
strategies pass without false errors.

@settings(max_examples=200, deadline=None) keeps the CI S1 shard fast and
avoids Hypothesis' per-example deadline flakiness.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from blockchecks.engine.conf_builder import escape_conf_lt, split_cli_args
from blockchecks.engine.static_validator import validate_strategy

pytestmark = pytest.mark.unit

# Fast fuzz profile: 200 examples, no per-example deadline (CI-safe).
_FAST = settings(max_examples=200, deadline=None)


def _preset_lines() -> list[str]:
    """All non-comment lines from presets/strategies/* (real-world corpus)."""
    lines: list[str] = []
    base = Path(__file__).resolve().parents[2] / "presets" / "strategies"
    if not base.is_dir():
        return []
    for p in sorted(base.glob("*")):
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                lines.append(s)
    return lines


# ── no unexpected exceptions on arbitrary text ─────────────────────────


@_FAST
@given(st.text(max_size=300))
def test_validate_strategy_never_raises_on_arbitrary_text(raw: str) -> None:
    result = validate_strategy(raw)
    assert isinstance(result.issues, list)
    for issue in result.issues:
        assert issue.code
        assert issue.message
        assert issue.severity in ("error", "warning", "info")


@_FAST
@given(st.text(max_size=300))
def test_split_cli_args_never_raises(raw: str) -> None:
    # Must return a list of strings, never throw.
    out = split_cli_args(raw)
    assert isinstance(out, list)
    assert all(isinstance(t, str) for t in out)


@_FAST
@given(st.text(max_size=300))
def test_escape_conf_lt_never_raises(raw: str) -> None:
    out = escape_conf_lt(raw)
    assert isinstance(out, str)
    assert "<" not in out.replace("\\<", "")


@_FAST
@given(st.text(max_size=300))
def test_strategy_traits_never_raises(raw: str) -> None:
    from blockchecks.engine.adaptive_queue import strategy_traits

    out = strategy_traits(raw)
    assert isinstance(out, tuple)
    assert all(isinstance(t, str) for t in out)


# ── hostile numeric / unicode input ────────────────────────────────────


@_FAST
@given(st.integers(min_value=-(10**15), max_value=10**15))
def test_validate_strategy_extreme_ttl(value: int) -> None:
    result = validate_strategy(f"fake:blob=stun:repeats=6:ttl={value}")
    if 0 <= value <= 255:
        assert result.is_valid
    else:
        assert any(i.code == "invalid_ttl" for i in result.issues)


@_FAST
@given(st.integers(min_value=-(2**31) - 5, max_value=2**31 + 5))
def test_validate_strategy_tcp_ts_int32(value: int) -> None:
    result = validate_strategy(f"fake:blob=stun:repeats=6:tcp_ts={value}")
    if -(2**31) <= value <= 2**31 - 1:
        assert result.is_valid
    else:
        assert any(i.code == "invalid_tcp_ts" for i in result.issues)


@_FAST
@given(st.text(alphabet="\ud800\udfff", max_size=100))
def test_validate_strategy_surrogate_pairs(raw: str) -> None:
    # Lone surrogates must not crash validation.
    result = validate_strategy(f"fake:blob=stun:repeats=6:{raw}")
    assert isinstance(result.issues, list)


@_FAST
@given(st.text(alphabet='abc:="\\<>0123456789-_', max_size=200))
def test_validate_strategy_specials(raw: str) -> None:
    result = validate_strategy(raw)
    assert isinstance(result.issues, list)


# ── invariant: real presets never yield false errors ───────────────────


@_FAST
@given(st.sampled_from(sorted(set(_preset_lines()))))
def test_real_presets_have_no_errors(line: str) -> None:
    result = validate_strategy(line)
    errors = [i for i in result.issues if i.severity == "error"]
    assert not errors, f"false error for real preset: {line!r} -> {[i.code for i in errors]}"


# ── dedup: repeated calls are stable (no shared mutable state) ──────────


@_FAST
@given(st.text(max_size=200))
def test_validate_strategy_is_deterministic(raw: str) -> None:
    a = validate_strategy(raw)
    b = validate_strategy(raw)
    assert [i.code for i in a.issues] == [i.code for i in b.issues]
