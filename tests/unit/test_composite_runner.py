"""Unit tests for composite_runner — single-netns composite config testing."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.checkers.composite_runner import (
    _valid_domain,
    normalize_domains,
    run,
)

pytestmark = pytest.mark.unit


def test_valid_domain():
    assert _valid_domain("discord.com") is True
    assert _valid_domain("a") is True
    assert _valid_domain("") is False
    assert _valid_domain("x" * 253) is False
    assert _valid_domain("has space.com") is False


def test_normalize_domains_default():
    from blockchecks.checkers.composite_runner import DOMAINS

    assert normalize_domains(None) == DOMAINS
    assert normalize_domains([]) == DOMAINS


def test_normalize_domains_split_dedupe():
    assert normalize_domains(["a.com,b.com", "b.com", "  c.com "]) == [
        "a.com",
        "b.com",
        "c.com",
    ]
    assert normalize_domains(["a.com", "", "a.com"]) == ["a.com"]


def test_run_config_not_found(tmp_path):
    rc = asyncio.run(run(str(tmp_path / "missing.conf"), ["discord.com"]))
    assert rc == 1


def test_run_invalid_domain_records_fail(tmp_path):
    conf = tmp_path / "c.conf"
    conf.write_text("--qnum=200\n")
    runner = AsyncMock()
    runner.start = AsyncMock()
    runner.stop = AsyncMock()
    pool = AsyncMock()
    pool.acquire = AsyncMock(return_value="ns1")
    pool.release = AsyncMock()
    runner.pool = pool
    with (
        patch("blockchecks.checkers.composite_runner.AsyncTestRunner", return_value=runner),
        patch("blockchecks.checkers.composite_runner.get_ns_firewall") as get_fw,
    ):
        get_fw.return_value = MagicMock()
        rc = asyncio.run(run(str(conf), ["not a domain", "discord.com"]))
    # invalid domain → no worker call; valid domain → worker call
    assert rc == 1  # both invalid/worker-fail → no passes


def test_run_success(tmp_path):
    conf = tmp_path / "c.conf"
    conf.write_text("--qnum=200\n")
    runner = AsyncMock()
    runner.start = AsyncMock()
    runner.stop = AsyncMock()
    pool = AsyncMock()
    pool.acquire = AsyncMock(return_value="ns1")
    pool.release = AsyncMock()
    runner.pool = pool
    data = {"success": True, "http_code": 200, "latency_ms": 50, "error": ""}
    with (
        patch("blockchecks.checkers.composite_runner.AsyncTestRunner", return_value=runner),
        patch("blockchecks.checkers.composite_runner.start_daemon", new=MagicMock()),
        patch(
            "blockchecks.checkers.composite_runner.invoke_curl_probe_worker",
            return_value=data,
        ),
        patch("blockchecks.checkers.composite_runner.get_ns_firewall") as get_fw,
    ):
        fw = MagicMock()
        get_fw.return_value = fw
        rc = asyncio.run(run(str(conf), ["discord.com"], timeout=3.0))
    assert rc == 0
    assert fw.attach.call_count == 2
    runner.start.assert_awaited_once()
    runner.stop.assert_awaited_once()
    pool.acquire.assert_awaited_once()
    pool.release.assert_awaited_once()
