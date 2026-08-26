"""Tests for HTTP/3 strategy generation and the QUIC checker."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from blockchecks.checkers.http3 import check_http3, supports_http3
from blockchecks.engine.async_runner import _build_quic_nfqws_lines
from blockchecks.engine.generators.standard import StandardGenerator
from blockchecks.engine.matrix_generator import MatrixGenerator

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_standard_quic_families():
    gen = StandardGenerator(strategy_types=["quic_fake", "quic_ipfrag"])
    items = await gen.generate(protocol="quic", scan_level="fast", max_count=30)
    assert items
    assert all(i.protocol == "quic" for i in items)
    strategies = "\n".join(i.strategy for i in items)
    assert "fake_default_quic" in strategies
    assert "ipfrag" in strategies


@pytest.mark.asyncio
async def test_matrix_generate_quic():
    gen = MatrixGenerator()
    items = await gen.generate_quic(
        sources=["standard_quic"],
        scan_level="single",
        max_count=5,
    )
    assert len(items) >= 1
    assert items[0].protocol == "quic"


def test_build_quic_nfqws_config_inline():
    lines = _build_quic_nfqws_lines("fake:blob=fake_default_quic:repeats=11")
    text = "\n".join(lines)
    assert "--filter-udp=443" in text
    assert "--filter-l7=quic" in text
    assert "--payload=quic_initial" in text
    assert "fake_default_quic" in text


def test_build_quic_nfqws_config_cli():
    strat = (
        "--filter-udp=443 --payload=quic_initial --lua-desync=fake:blob=quic_initial:repeats=6"
    )
    lines = _build_quic_nfqws_lines(strat)
    text = "\n".join(lines)
    assert "--filter-udp=443" in text
    assert "quic_initial" in text
    assert any(line.startswith("--blob=quic_initial:") for line in lines)


def test_supports_http3_true_on_connection_error():
    from curl_cffi.requests import RequestsError

    session = MagicMock()
    session.__enter__.return_value = session
    session.__exit__.return_value = False
    session.get.side_effect = RequestsError("connection refused")

    with patch("blockchecks.checkers.http3.curl_cffi.Session", return_value=session):
        assert supports_http3() is True


def test_check_http3_success():
    resp = MagicMock()
    resp.status_code = 200
    resp.headers = {"Content-Length": "1234"}
    resp.http_version = "v3"

    session = MagicMock()
    session.__enter__.return_value = session
    session.__exit__.return_value = False
    session.head.return_value = resp

    with patch("blockchecks.checkers.http3.curl_cffi.Session", return_value=session) as Sess:
        result = check_http3("example.com", timeout=5.0)
    assert result.success is True
    assert result.http_status == 200
    assert Sess.call_args.kwargs.get("http_version") == "v3only"
    session.head.assert_called_once()


def test_check_http3_non_2xx_fails():
    resp = MagicMock()
    resp.status_code = 503
    resp.headers = {}
    resp.http_version = "v3"

    session = MagicMock()
    session.__enter__.return_value = session
    session.__exit__.return_value = False
    session.head.return_value = resp

    with patch("blockchecks.checkers.http3.curl_cffi.Session", return_value=session):
        result = check_http3("example.com", timeout=5.0)
    assert result.success is False
    assert result.http_status == 503
    assert result.error == "http 503"


def test_check_http3_requests_error():
    from curl_cffi.requests import RequestsError

    session = MagicMock()
    session.__enter__.return_value = session
    session.__exit__.return_value = False
    session.head.side_effect = RequestsError("quic timeout")

    with patch("blockchecks.checkers.http3.curl_cffi.Session", return_value=session):
        result = check_http3("example.com", timeout=5.0)
    assert result.success is False
    assert result.error == "timeout"


def test_supports_http3_false_when_not_supported():
    from curl_cffi.requests import RequestsError

    session = MagicMock()
    session.__enter__.return_value = session
    session.__exit__.return_value = False
    session.get.side_effect = RequestsError("option not supported")

    with patch("blockchecks.checkers.http3.curl_cffi.Session", return_value=session):
        assert supports_http3() is False


def test_quic_fallback_variants_adds_badsum_and_ttl():
    from blockchecks.engine.async_runner import _quic_fallback_variants

    variants = _quic_fallback_variants("fake:blob=quic_google:repeats=6")
    assert variants == [
        "fake:blob=quic_google:repeats=6:badsum",
        "fake:blob=quic_google:repeats=6:ip_ttl=1",
    ]


def test_quic_fallback_variants_skips_existing(monkeypatch):
    monkeypatch.delenv("BLOCKCHECKS_QUIC_FALLBACK", raising=False)
    from blockchecks.engine.async_runner import _quic_fallback_variants

    assert _quic_fallback_variants("fake:blob=X:badsum") == ["fake:blob=X:badsum:ip_ttl=1"]
    assert _quic_fallback_variants("fake:blob=X:ip_ttl=1") == ["fake:blob=X:ip_ttl=1:badsum"]
    assert _quic_fallback_variants("fake:blob=X:badsum:ip_ttl=1") == []


def test_quic_fallback_variants_skips_config_and_disabled(monkeypatch):
    from blockchecks.engine.async_runner import _quic_fallback_variants

    assert _quic_fallback_variants("--qnum=201\n--filter-udp=443") == []
    monkeypatch.setenv("BLOCKCHECKS_QUIC_FALLBACK", "0")
    assert _quic_fallback_variants("fake:blob=X") == []
    monkeypatch.delenv("BLOCKCHECKS_QUIC_FALLBACK", raising=False)


def test_is_quic_dropped():
    from blockchecks.engine.async_runner import _is_quic_dropped

    assert _is_quic_dropped("timeout after 5000ms") is True
    assert _is_quic_dropped("Connection timed out") is True
    assert _is_quic_dropped("ngtcp2_conn_writev_stream failed") is False
    assert _is_quic_dropped("SSL: no alternative certificate") is False


@pytest.mark.asyncio
async def test_quic_fallback_uses_short_timeout_for_fallback_variants():
    """Fallback variants must use a shorter timeout (drop happens instantly)."""
    from unittest.mock import patch

    from blockchecks.engine.async_runner import AsyncTestRunner
    from blockchecks.engine.generators.base import StrategyItem

    calls = []

    def fake_run_quic(ns, strategy, domain, timeout, *a, **k):
        calls.append((strategy, timeout))
        return {
            "success": False,
            "http_code": 0,
            "latency_ms": 0,
            "content_len": 0,
            "error": "Connection timed out",
        }

    runner = AsyncTestRunner(pool_size=1)
    runner.secure_dns = False
    runner.dns_cache = None
    runner.dns_audit = {}
    item = StrategyItem(
        label="quic_fake", strategy="fake:blob=quic_google:repeats=6", protocol="quic"
    )

    # AsyncTestRunner.test_quic uses self.pool.acquire + asyncio.to_thread.
    # Patch acquire to return a ns and _run_quic_check to capture timeouts.

    async def fake_acquire():
        return "bs-quic-t"

    async def fake_release(ns):
        pass

    with (
        patch.object(runner.pool, "acquire", new=fake_acquire),
        patch.object(runner.pool, "release", new=fake_release),
        patch("blockchecks.engine.async_runner._run_quic_check", side_effect=fake_run_quic),
    ):
        result = await runner.test_quic(item, "googlevideo.com", timeout=5.0)

    # base uses full timeout 5.0; fallbacks use min(5, 3) = 3.0
    assert len(calls) == 3
    assert calls[0][1] == 5.0
    assert calls[1][1] == 3.0
    assert calls[2][1] == 3.0
    assert result.success is False
