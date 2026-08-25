"""Unit tests for unified wssize retry policy."""

from __future__ import annotations

import pytest

from blockchecks.engine.wssize_retry import WSSIZE_RETRY, WssizeRetryPolicy

pytestmark = pytest.mark.unit


def test_retry_timeout_caps_at_one_point_five() -> None:
    assert WSSIZE_RETRY.retry_timeout(5.0) == 1.5
    assert WSSIZE_RETRY.retry_timeout(1.0) == 1.0


def test_should_retry_tls12_fail() -> None:
    data = {"success": False}
    assert WSSIZE_RETRY.should_retry(
        data,
        try_wssize=True,
        protocol="tls12",
        strategy="fake:blob=stun:repeats=6",
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"data": {"success": True}},
        {"try_wssize": False},
        {"protocol": "tls13"},
        {"strategy": "wssize:wsize=1:scale=6"},
        {"is_config": True},
    ],
)
def test_should_retry_negative_cases(kwargs: dict) -> None:
    base = {
        "data": {"success": False},
        "try_wssize": True,
        "protocol": "tls12",
        "strategy": "fake:blob=stun:repeats=6",
        "is_config": False,
    }
    base.update(kwargs)
    assert not WSSIZE_RETRY.should_retry(**base)


def test_policy_cmd_constant() -> None:
    assert WssizeRetryPolicy().cmd == "wssize:wsize=1:scale=6"
