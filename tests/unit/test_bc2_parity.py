"""Tests for standard-family expansions that match blockcheck2 lists."""

from __future__ import annotations

import pytest

from blockchecks.engine.generators.custom import UserMatrixGenerator
from blockchecks.engine.generators.families._helpers import (
    _with_ack_drop,
    _with_ip6_send_drop,
    _with_send_md5,
)
from blockchecks.engine.generators.standard import (
    ALL_FOOLINGS_IPV6,
    ALL_FOOLINGS_TCP,
    FAST_FOOLINGS_IPV6,
    StandardGenerator,
)

pytestmark = pytest.mark.unit


def test_all_foolings_include_badsum_and_def_inc_order():
    assert "badsum" in ALL_FOOLINGS_TCP
    assert "tcp_md5" in ALL_FOOLINGS_TCP
    assert len(ALL_FOOLINGS_IPV6) >= 5
    assert "ip6_destopt" in ALL_FOOLINGS_IPV6
    assert "ip6_ah" in ALL_FOOLINGS_IPV6
    assert len(FAST_FOOLINGS_IPV6) >= 2


def test_companion_helpers():
    assert "pktmod:ip_ttl=1" in _with_ack_drop("fake:blob=stun:repeats=6")
    assert "--payload=empty" in _with_ack_drop("fake:blob=stun:repeats=6")
    assert "send:tcp_md5" in _with_send_md5("fake:blob=stun:repeats=6:tcp_md5")
    assert _with_ip6_send_drop("ip6_hopbyhop") == "send:ip6_hopbyhop\ndrop"


@pytest.mark.asyncio
async def test_http_simple_has_domcase_unixeol():
    gen = StandardGenerator(strategy_types=["http_simple"])
    items = await gen.generate(protocol="http", scan_level="fast", max_count=20)
    joined = "\n".join(i.strategy for i in items)
    assert "http_domcase" in joined
    assert "http_unixeol" in joined


@pytest.mark.asyncio
async def test_oob_emits_in_range():
    gen = StandardGenerator(strategy_types=["oob"])
    items = await gen.generate(protocol="tls12", scan_level="fast", max_count=10)
    assert any("--in-range=-s1" in i.strategy for i in items)
    assert any("oob:urp=" in i.strategy for i in items)


@pytest.mark.asyncio
async def test_fake_has_null_blob_ackdrop_sendmd5_badsum():
    gen = StandardGenerator(strategy_types=["fake"])
    items = await gen.generate(protocol="tls12", scan_level="fast", max_count=800)
    text = "\n---\n".join(i.strategy for i in items)
    assert "0x00000000" in text
    assert "badsum" in text
    assert "pktmod:ip_ttl=1" in text
    assert "send:tcp_md5" in text
    assert any("ip6_hopbyhop" in i.strategy for i in items)


@pytest.mark.asyncio
async def test_syndata_bare_and_hostfake():
    gen = StandardGenerator(strategy_types=["syndata"])
    items = await gen.generate(protocol="tls12", scan_level="fast", max_count=50)
    assert any(i.strategy.strip() == "syndata" or i.strategy.startswith("syndata\n") for i in items)
    assert any("hostfakesplit" in i.strategy for i in items)


@pytest.mark.asyncio
async def test_udp_discord_ttl_stun():
    gen = StandardGenerator(strategy_types=["udp_discord"])
    items = await gen.generate(protocol="udp_voice", scan_level="fast", max_count=40)
    text = "\n".join(i.strategy for i in items)
    assert "discord_udp" in text
    assert "blob=stun" in text
    assert "ip_ttl=5" in text
    assert "ip_autottl=" in text


@pytest.mark.asyncio
async def test_quic_fake_badsum_and_ip6_drop():
    gen = StandardGenerator(strategy_types=["quic_fake"])
    items = await gen.generate(protocol="quic", scan_level="full", max_count=200)
    text = "\n---\n".join(i.strategy for i in items)
    assert "badsum" in text
    assert "send:ip6_hopbyhop" in text
    assert "\ndrop" in text or text.endswith("drop")


@pytest.mark.asyncio
async def test_user_matrix_backslash_n(tmp_path):
    path = tmp_path / "m.txt"
    path.write_text(
        "fake:blob=stun:repeats=6\\n--payload=empty\\npktmod:ip_ttl=1\n"
        "fake:blob=google:repeats=6\n",
        encoding="utf-8",
    )
    items = await UserMatrixGenerator(str(path)).generate("tls12")
    assert len(items) == 2
    assert "\n" in items[0].strategy
    assert "pktmod:ip_ttl=1" in items[0].strategy
