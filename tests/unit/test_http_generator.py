"""BC2-9: HTTP :80 standard generator and nfqws2 config."""

from __future__ import annotations

import pytest

from blockchecks.engine.async_runner import _build_inline_nfqws_lines
from blockchecks.engine.generators.standard import StandardGenerator
from blockchecks.engine.matrix_generator import MatrixGenerator

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_standard_http_families():
    gen = StandardGenerator(strategy_types=["http_simple", "http_fake"])
    items = await gen.generate(protocol="http", scan_level="fast", max_count=30)
    assert items
    assert all(i.protocol == "http" for i in items)
    strategies = "\n".join(i.strategy for i in items)
    assert "http_hostcase" in strategies
    assert "http_methodeol" in strategies
    assert "fake_default_http" in strategies


@pytest.mark.asyncio
async def test_matrix_generate_http():
    gen = MatrixGenerator()
    items = await gen.generate_http(
        sources=["standard_http"],
        scan_level="single",
        max_count=5,
    )
    assert len(items) >= 1
    assert items[0].protocol == "http"


def test_build_http_nfqws_config():
    lines = _build_inline_nfqws_lines("fake:blob=fake_default_http:tcp_ts=-1000", "http")
    text = "\n".join(lines)
    assert "--filter-tcp=80" in text
    assert "--filter-l7=http" in text
    assert "--payload=http_req" in text
    assert "fake_default_http" in text


def test_build_tls_nfqws_config_unchanged():
    lines = _build_inline_nfqws_lines("fake:blob=stun:repeats=6", "tls12")
    text = "\n".join(lines)
    assert "--filter-tcp=443" in text
    assert "--filter-l7=tls" in text
    assert "--payload=tls_client_hello" in text
