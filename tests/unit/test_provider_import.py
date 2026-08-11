"""Tests for provider_summary import (A5)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

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


# ── added: extract / merge / to_shortlist / report / main ─────────────


def test_extract_strategies():
    from blockchecks.provider_import import extract_strategies

    summary = {
        "custom_strategies": {
            "tls12": ["fake:blob=stun:repeats=6", "# comment", ""],
            "udp": ["fake:blob=discord_udp:repeats=6"],
        }
    }
    out = extract_strategies(summary)
    assert out["tls12"] == ["fake:blob=stun:repeats=6"]
    assert out["udp"] == ["fake:blob=discord_udp:repeats=6"]


def test_merge_into_user_matrix(tmp_path):
    from blockchecks.provider_import import merge_into_user_matrix

    existing = tmp_path / "m.yaml"
    existing.write_text("old:strategy\n")
    sf = tmp_path / "summary.json"
    sf.write_text('{"provider_id": "p1", "custom_strategies": {"tls12": ["fake:blob=stun:repeats=6"]}}')
    path = merge_into_user_matrix(sf, existing)
    content = Path(path).read_text()
    assert "old:strategy" in content
    assert "fake:blob=stun:repeats=6" in content


def test_provider_summary_to_shortlist():
    from blockchecks.provider_import import provider_summary_to_shortlist

    summary = {
        "provider_id": "p1",
        "generated_at": "2026-01-01",
        "custom_strategies": {"tls12": ["fake:a"]},
        "shortlist": {"d.com": {"tls12": "fake:b"}},
    }
    sl = provider_summary_to_shortlist(summary)
    assert sl["schema"] == "blockchecks.shortlist/v1"
    assert sl["tcp"][0]["strategy"] == "fake:a"
    assert sl["domains"] == ["d.com"]
    assert sl["common_tcp"] == []


def test_build_import_report():
    from blockchecks.provider_import import build_import_report

    summary = {
        "provider_id": "p1",
        "custom_strategies": {"tls12": ["fake:a"], "udp": ["fake:u"]},
        "shortlist": {"d.com": {"tls12": "fake:b"}},
    }
    report = build_import_report(summary)
    assert "p1" in report


def test_main_ok(tmp_path):
    from blockchecks.provider_import import main

    f = tmp_path / "summary.json"
    f.write_text('{"provider_id": "p1", "custom_strategies": {"tls12": ["fake:a"]}}')
    with patch("blockchecks.provider_import.write_shortlist_presets",
               return_value={"tls12": "x"}):
        rc = main(["-i", str(f)])
    assert rc == 0
