"""Tests for provider_summary import (A5)."""

from __future__ import annotations

import json

import pytest

from blockchecks.provider_import import (
    extract_strategies,
    load_provider_summary,
    write_shortlist_presets,
)

pytestmark = pytest.mark.unit


def test_normalize_cli_strategy():
    summary = {
        "provider_id": "test",
        "generated_at": "2026-01-01T00:00:00Z",
        "custom_strategies": {
            "tls12": [
                "--payload tls_client_hello --lua-desync=fake:blob=stun:repeats=6",
                "hostfakesplit:nofake2:tcp_ts=-1000:repeats=1",
            ]
        },
    }
    got = extract_strategies(summary)
    assert got["tls12"][0] == "fake:blob=stun:repeats=6"
    assert "hostfakesplit" in got["tls12"][1]


def test_write_shortlist_presets(tmp_path):
    summary = {
        "provider_id": "fryazino",
        "generated_at": "2026-01-01",
        "shortlist": {"discord.com": {"tls12": "fake:blob=stun:repeats=6:tcp_ts=-1000"}},
    }
    written = write_shortlist_presets(summary, tmp_path, prefix="test")
    assert "tls12" in written
    text = (tmp_path / "test-tls12.tls").read_text()
    assert "fake:blob=stun" in text


def test_load_roundtrip(tmp_path):
    path = tmp_path / "provider_summary.json"
    data = {"provider_id": "x", "custom_strategies": {"quic": ["fake:blob=quic_google:repeats=6"]}}
    path.write_text(json.dumps(data))
    assert load_provider_summary(path)["provider_id"] == "x"


def test_shortlist_v1_import_presets(tmp_path):
    from blockchecks.shortlist_import import import_shortlist

    shortlist = {
        "schema": "blockchecks.shortlist/v1",
        "domains": ["discord.com"],
        "tcp": [
            {"label": "w", "strategy": "fake:blob=stun:repeats=6", "domains_pass": ["discord.com"]}
        ],
        "udp": [],
        "quic": [],
    }
    path = tmp_path / "shortlist.json"
    path.write_text(json.dumps(shortlist))
    result = import_shortlist(path, out_dir=tmp_path, prefix="provider")
    assert "tls12" in result["presets"]
