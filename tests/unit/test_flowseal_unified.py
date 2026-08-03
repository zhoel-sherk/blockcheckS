"""Flowseal generator + baked blobs coverage."""

from __future__ import annotations

import pytest

from blockchecks.engine.blob_aliases import FLOWSEAL_CORE_ALIASES, resolve_blob_path
from blockchecks.engine.config import BLOB_DIR, REPO_BLOBS_DIR
from blockchecks.engine.generators.flowseal import FlowsealGenerator


@pytest.mark.unit
def test_blob_dir_prefers_repo_blobs():
    assert BLOB_DIR == REPO_BLOBS_DIR or "blobs" in BLOB_DIR


@pytest.mark.unit
def test_flowseal_core_aliases_resolve_without_network():
    for alias in FLOWSEAL_CORE_ALIASES:
        path = resolve_blob_path(alias)
        assert path, f"missing baked blob for {alias}"
        assert path.endswith(".bin")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_flowseal_generator_covers_techniques_and_protocols():
    gen = FlowsealGenerator()
    tcp = await gen.generate("tls12", scan_level="fast", max_count=80)
    assert len(tcp) >= 13  # seeds
    joined = "\n".join(i.strategy for i in tcp)
    for needle in (
        "fake:blob=",
        "multisplit",
        "seqovl=480",
        "fakedsplit",
        "hostfakesplit",
        "multidisorder",
        "syndata",
        "badsid",
        "tls_mod=",
        "ip_id=zero",
    ):
        assert needle in joined, needle

    big = await gen.generate("tls12", scan_level="fast", max_count=5000)
    assert len(big) > 1000

    quic = await gen.generate("quic", scan_level="fast", max_count=50)
    assert quic
    assert all(i.protocol == "quic" for i in quic)

    udp = await gen.generate("udp_voice", scan_level="fast", max_count=50)
    assert udp
    assert all(i.protocol == "udp_voice" for i in udp)
    assert any("discord_udp" in i.strategy or "game_udp" in i.strategy for i in udp)
