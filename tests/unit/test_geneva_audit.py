"""Geneva/Flowseal audit coverage: rst_fake, synack, wssize, geneva_fool,
Flowseal badseq/tls_mod=none/altorder gaps, repeats=14 in TCP pool."""

from __future__ import annotations

import asyncio
import re

import pytest

from blockchecks.engine.generators.flowseal import FlowsealGenerator
from blockchecks.engine.generators.standard import (
    ALL_REPEATS,
    FAST_FOOLINGS_TCP,
    FAST_REPEATS,
    StandardGenerator,
)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_rst_fake_covers_geneva_ack_rst():
    gen = StandardGenerator(strategy_types=["rst_fake"])
    items = await gen.generate(protocol="tls12", scan_level="fast", max_count=100)
    text = "\n---\n".join(i.strategy for i in items)
    # Geneva 10-15: ACK→RST duplicate on empty ACK
    assert "rst:badsum" in text
    assert "rst:ip_ttl=" in text
    assert "rst:tcp_md5" in text
    assert "rst:rstack:" in text
    # exotic flag fakes (Geneva 16-18 ≈ FRAPUEN/FREACN/FRAPUN)
    assert "tcp_flags_set=" in text
    assert "--payload=empty --out-range=s1<d1" in text


@pytest.mark.unit
@pytest.mark.asyncio
async def test_synack_covers_geneva_syn_sa():
    gen = StandardGenerator(strategy_types=["synack"])
    items = await gen.generate(protocol="tls12", scan_level="fast", max_count=100)
    text = "\n".join(i.strategy for i in items)
    assert "synack" in text
    assert "synack_split:mode=" in text
    assert "acksyn" in text


@pytest.mark.unit
@pytest.mark.asyncio
async def test_wssize_companion():
    gen = StandardGenerator(strategy_types=["wssize"])
    items = await gen.generate(protocol="tls12", scan_level="fast", max_count=100)
    text = "\n".join(i.strategy for i in items)
    assert "wssize:wsize=1:scale=6" in text
    assert "multisplit" in text


@pytest.mark.unit
@pytest.mark.asyncio
async def test_geneva_fool_hooks():
    gen = StandardGenerator(strategy_types=["geneva_fool"])
    items = await gen.generate(protocol="tls12", scan_level="fast", max_count=100)
    text = "\n".join(i.strategy for i in items)
    assert "send:fool=bs_dataofs" in text
    assert "fool=bs_iplen=" in text
    assert "fool=bs_corrupt_load" in text
    assert "fool=bs_corrupt_wscale" in text
    assert "fool=bs_corrupt_uto" in text
    # no doubled fool=
    assert "fool=fool=" not in text


@pytest.mark.unit
@pytest.mark.asyncio
async def test_flowseal_badseq_increment_gaps():
    gen = FlowsealGenerator()
    items = await gen.generate(protocol="tls12", scan_level="full", max_count=100000)
    text = "\n".join(i.strategy for i in items)
    # ALT4/ALT8/FTA_ALT2: badseq via tcp_seq increment (2/1000/10000000)
    for inc in ("2", "1000", "10000000"):
        assert f"tcp_seq={inc}" in text, f"badseq increment {inc} missing"
    # ALT8/ALT10: fake-tls-mod=none
    assert "tls_mod=none" in text
    # ALT3: hostfakesplit-mod altorder
    assert "altorder=1" in text
    # ALT5: syndata + multidisorder
    assert "syndata\nmultidisorder" in text
    # ALT7: split-pos=2,sniext+1
    assert "pos=2,sniext+1" in text


@pytest.mark.unit
@pytest.mark.asyncio
async def test_repeats_14_in_tcp_pool():
    assert 14 in ALL_REPEATS
    assert 14 in FAST_REPEATS
    gen = StandardGenerator(strategy_types=["fake"])
    items = await gen.generate(protocol="tls12", scan_level="full", max_count=100000)
    text = "\n".join(i.strategy for i in items)
    assert re.search(r"repeats=14", text)


@pytest.mark.unit
def test_fast_foolings_now_include_seq_flags():
    joined = "\n".join(FAST_FOOLINGS_TCP)
    assert "tcp_seq=-3000" in joined
    assert "tcp_seq=1000000" in joined
    assert "tcp_flags_unset=ACK" in joined
    assert "tcp_flags_set=SYN" in joined


@pytest.mark.unit
def test_geneva_lua_hooks_file_present():
    from pathlib import Path

    from blockchecks.engine.config import REPO_LUA_DIR

    p = Path(REPO_LUA_DIR) / "geneva.lua"
    assert p.is_file(), "lua/blockchecks/geneva.lua missing"
    text = p.read_text(encoding="utf-8")
    for fn in ("bs_dataofs", "bs_iplen", "bs_corrupt_load", "bs_corrupt_wscale", "bs_corrupt_uto"):
        assert f"function {fn}" in text, fn
    # no bit32 (not available in zapret lua runtime)
    assert "bit32" not in text
