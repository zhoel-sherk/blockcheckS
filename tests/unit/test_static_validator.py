"""Deterministic table-driven tests for engine.static_validator."""

from __future__ import annotations

import pytest

from blockchecks.engine.static_validator import (
    StrategyValidationResult,
    ValidationIssue,
    validate_strategies,
    validate_strategy,
)

pytestmark = pytest.mark.unit


# (strategy, expected error codes, expected warning/info codes)
VALID_CASES = [
    "fake:blob=stun:repeats=6:tcp_ts=-1000",
    "fake:blob=stun:repeats=6",
    "fake:blob=0x00000000:repeats=6",
    "fake:blob=max_ru:repeats=6:tcp_ts=-1000",
    "fake:blob=discord_udp:repeats=6",
    "hostfakesplit:host=ozon.ru:tcp_ts=-1000:tcp_md5:repeats=1",
    "multisplit:pos=1:seqovl=568:seqovl_pattern=4pda",
    "fakedsplit:pos=1:pattern=0x00000000:tcp_ts=-1000:repeats=1",
    "fake:blob=stun:repeats=6:ttl=127",
    "fake:blob=stun:repeats=6:ttl=0",
    "fake:blob=stun:repeats=6:tcp_ts=-1000:tcp_ack=-66000",
    "fake:blob=stun:repeats=6:ip_ttl=64",
    "fake:blob=stun:repeats=6\\nfake:blob=max_ru:repeats=6",  # backslash-n multi-core
    "fake:blob=stun:repeats=6:repeats=6",  # dup repeats ok
]


@pytest.mark.parametrize("strategy", VALID_CASES)
def test_valid_strategies_have_no_errors(strategy: str) -> None:
    result = validate_strategy(strategy)
    assert result.is_valid, f"expected valid: {strategy!r} -> {[i.code for i in result.issues]}"


ERROR_CASES = [
    # (strategy, expected error codes)
    ("", ["empty_strategy"]),
    ("   ", ["empty_strategy"]),
    ("fake:repeats=6", ["fake_without_blob"]),
    ("dupfake:repeats=6", ["fake_without_blob"]),
    ("fake:blob=nonexistent_blob_xyz:repeats=6", ["unknown_blob"]),
    ("fake:blob=stun:repeats=0", ["repeats_range"]),
    ("fake:blob=stun:repeats=-3", ["repeats_range"]),
    ("fake:blob=stun:repeats=6:ttl=999", ["invalid_ttl"]),
    ("fake:blob=stun:repeats=6:ttl=-1", ["invalid_ttl"]),
    ("fake:blob=stun:repeats=6:ip_ttl=300", ["invalid_ip_ttl"]),
    ("fake:blob=stun:repeats=6:tcp_ts=abc", ["non_numeric_param"]),
    ("fake:blob=stun:repeats=6:tcp_ts=99999999999999999999", ["invalid_tcp_ts"]),
    ('fake:blob=stun:repeats=6:unbalanced="quote', ["malformed"]),
]


@pytest.mark.parametrize("strategy,expected", ERROR_CASES)
def test_invalid_strategies_report_errors(strategy: str, expected: list[str]) -> None:
    result = validate_strategy(strategy)
    codes = [i.code for i in result.issues if i.severity == "error"]
    for code in expected:
        assert code in codes, f"missing {code} for {strategy!r}: got {codes}"


WARNING_CASES = [
    # split family without pos -> warning, but still valid (no error)
    ("multisplit:seqovl=568", ["split_without_pos"]),
    ("fakedsplit:tcp_ts=-1000", ["split_without_pos"]),
    # repeats=21 -> warning (not error)
    ("fake:blob=stun:repeats=21", ["repeats_range"]),
]


@pytest.mark.parametrize("strategy,expected", WARNING_CASES)
def test_warning_cases_are_valid_but_flag_warnings(strategy: str, expected: list[str]) -> None:
    result = validate_strategy(strategy)
    assert result.is_valid, f"expected valid-with-warning: {strategy!r}"
    warning_codes = [i.code for i in result.issues if i.severity == "warning"]
    for code in expected:
        assert code in warning_codes, f"missing warning {code}: got {warning_codes}"


def test_unescaped_lt_is_info() -> None:
    result = validate_strategy("fake:blob=stun:repeats=6:pos=1<s3")
    assert result.is_valid
    codes = [i.code for i in result.issues]
    assert "unescaped_lt" in codes
    assert all(i.severity != "error" for i in result.issues)


def test_result_errors_property() -> None:
    result = validate_strategy("fake:blob=stun:repeats=0")
    assert not result.is_valid
    assert [i.code for i in result.errors()] == ["repeats_range"]


def test_validate_strategies_batch() -> None:
    results = validate_strategies(
        ["fake:blob=stun:repeats=6", "fake:repeats=6", ""]
    )
    assert len(results) == 3
    assert results[0].is_valid
    assert not results[1].is_valid
    assert not results[2].is_valid


def test_validation_issue_default_severity() -> None:
    issue = ValidationIssue(code="x", message="y")
    assert issue.severity == "warning"


def test_strategy_validation_result_repr() -> None:
    r = StrategyValidationResult(strategy="abc")
    assert r.strategy == "abc"
    assert r.issues == []


def test_custom_lua_excluded_param_is_error() -> None:
    result = validate_strategy("dupfake:blob=stun:repeats=6:pos=1")
    codes = [i.code for i in result.issues if i.severity == "error"]
    assert "custom_lua_excluded" in codes


def test_custom_lua_undocumented_param_is_warning() -> None:
    result = validate_strategy("dupfake:blob=stun:repeats=6:mystery_param=1")
    assert result.is_valid  # warning only, not an error
    codes = [i.code for i in result.issues]
    assert "custom_lua_undocumented" in codes


def test_custom_lua_allowed_params_clean() -> None:
    result = validate_strategy("dupfake:blob=stun:repeats=6:tcp_ts=-1000")
    assert result.is_valid
    assert not [i for i in result.issues if i.code.startswith("custom_lua")]
