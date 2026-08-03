"""BC2-10: HTTP/3 QUIC generator and checker tests."""

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
    strat = "--filter-udp=443 --payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=6"
    lines = _build_quic_nfqws_lines(strat)
    text = "\n".join(lines)
    assert "--filter-udp=443" in text
    assert "fake_default_quic" in text


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
