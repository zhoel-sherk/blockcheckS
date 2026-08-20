"""Tests for shortlist v1 export and import."""

from __future__ import annotations

import json

import pytest

from blockchecks.engine.store import StateDB
from blockchecks.shortlist_export import SCHEMA, build_shortlist_entries, export_shortlist_json
from blockchecks.shortlist_import import (
    import_shortlist,
    load_shortlist,
    shortlist_to_provider_summary,
)

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_build_shortlist_schema_fields(temp_db: StateDB):
    await temp_db.log_tcp(
        "std_multi_stun+max_ru",
        "discord.com",
        "PASS",
        107.0,
        200,
        config_path="fake:blob=stun:repeats=6:tcp_ts=-1000\nfake:blob=max_ru:repeats=6:tcp_ts=-1000",
    )
    payload = await build_shortlist_entries(temp_db, domains=["discord.com"], limit=5)
    assert payload["schema"] == SCHEMA
    assert "generated_at" in payload
    assert payload["domains"] == ["discord.com"]
    assert payload["tcp"]
    assert payload["tcp"][0]["strategy"]


@pytest.mark.asyncio
async def test_export_shortlist_json_file(tmp_path):
    db_path = tmp_path / "test.db"
    out_path = tmp_path / "shortlist.json"
    db = StateDB(str(db_path))
    await db.init()
    await db.log_tcp(
        "s1", "discord.com", "PASS", 100.0, 200, config_path="fake:blob=stun:repeats=6"
    )
    await export_shortlist_json(db_path=str(db_path), domain="discord.com", output=str(out_path))
    data = json.loads(out_path.read_text())
    assert data["schema"] == SCHEMA
    assert data["tcp"]


def test_shortlist_import_roundtrip(tmp_path):
    shortlist = {
        "schema": SCHEMA,
        "generated_at": "2026-01-01T00:00:00Z",
        "source_db": "state.db",
        "domains": ["discord.com"],
        "tcp": [
            {
                "label": "winner",
                "strategy": "fake:blob=stun:repeats=6:tcp_ts=-1000",
                "domains_pass": ["discord.com"],
            }
        ],
        "udp": [],
        "quic": [],
        "common_tcp": [],
    }
    path = tmp_path / "shortlist.json"
    path.write_text(json.dumps(shortlist))
    loaded = load_shortlist(path)
    summary = shortlist_to_provider_summary(loaded)
    assert "tls12" in summary["custom_strategies"]
    result = import_shortlist(path, out_dir=tmp_path / "presets", prefix="rt", seed_db=False)
    assert "tls12" in result["presets"]
    text = (tmp_path / "presets" / "rt-tls12.tls").read_text()
    assert "fake:blob=stun" in text


@pytest.mark.asyncio
async def test_shortlist_seed_db(tmp_path):
    from blockchecks.shortlist_import import import_shortlist_async

    shortlist = {
        "schema": SCHEMA,
        "domains": ["discord.com"],
        "tcp": [
            {
                "label": "seeded",
                "strategy": "fake:blob=stun:repeats=6",
                "domains_pass": ["discord.com"],
            }
        ],
        "udp": [],
        "quic": [],
    }
    path = tmp_path / "shortlist.json"
    path.write_text(json.dumps(shortlist))
    db_path = tmp_path / "seed.db"
    await import_shortlist_async(path, db_path=str(db_path), seed_db=True, out_dir=tmp_path)
    db = StateDB(str(db_path))
    await db.init()
    working = await db.get_working_tcp("discord.com")
    assert "seeded" in working


# common_tcp / udp / quic / fallback / main
@pytest.mark.asyncio
async def test_build_shortlist_common_tcp_fallback(temp_db: StateDB):
    from blockchecks.shortlist_export import build_shortlist_entries

    payload = await build_shortlist_entries(temp_db, domains=["a.com", "b.com"], limit=3)
    assert payload["schema"] == SCHEMA


@pytest.mark.asyncio
async def test_build_shortlist_udp_quic_rows(temp_db: StateDB):
    from blockchecks.shortlist_export import build_shortlist_entries

    await temp_db.log_udp("u1", "voice", "PASS", 5.0, config_path="fake:blob=discord_udp")
    payload = await build_shortlist_entries(temp_db, domains=["discord.com"], limit=3)
    assert payload["udp"]


def test_shortlist_export_main(tmp_path):
    from unittest.mock import AsyncMock, patch

    from blockchecks.shortlist_export import main

    with patch(
        "blockchecks.shortlist_export.export_shortlist_json",
        new=AsyncMock(return_value={"schema": "blockchecks.shortlist/v1", "tcp": []}),
    ):
        rc = main(["--db", str(tmp_path / "x.db"), "--output", str(tmp_path / "o.json")])
    assert rc == 0
