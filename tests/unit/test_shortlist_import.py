"""Unit tests for shortlist_import — shortlist v1 → presets + DB seed."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.shortlist_import import (
    SCHEMA,
    import_shortlist,
    import_shortlist_async,
    load_shortlist,
    main,
    seed_state_db,
    shortlist_to_provider_summary,
)

pytestmark = pytest.mark.unit


def _shortlist(**over):
    data = {
        "schema": SCHEMA,
        "source_db": "test.db",
        "generated_at": "2026-01-01",
        "domains": ["discord.com"],
        "tcp": [
            {"label": "s1", "strategy": "fake:blob=stun:repeats=6", "latency_ms": 42.0}
        ],
        "udp": [
            {"label": "u1", "strategy": "fake:blob=discord_udp:repeats=6", "latency_ms": 10.0}
        ],
        "quic": [],
        "common_tcp": [
            {"strategy": "hostfakesplit:nofake2", "domains_pass": ["a.com"]}
        ],
    }
    data.update(over)
    return data


# ── load_shortlist ────────────────────────────────────────────────────


def test_load_shortlist_ok(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps(_shortlist()))
    data = load_shortlist(p)
    assert data["schema"] == SCHEMA


def test_load_shortlist_not_dict(tmp_path):
    p = tmp_path / "s.json"
    p.write_text("[]")
    with pytest.raises(ValueError):
        load_shortlist(p)


def test_load_shortlist_wrong_schema(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"schema": "other/v2"}))
    with pytest.raises(ValueError, match="unsupported schema"):
        load_shortlist(p)


# ── shortlist_to_provider_summary ─────────────────────────────────────


def test_summary_buckets():
    s = _shortlist()
    summary = shortlist_to_provider_summary(s)
    assert "tls12" in summary["custom_strategies"]
    assert summary["custom_strategies"]["tls12"] == ["fake:blob=stun:repeats=6"]
    assert "udp" in summary["custom_strategies"]
    assert summary["shortlist"]["a.com"]["tls12"] == "hostfakesplit:nofake2"


def test_summary_skips_non_dict_rows():
    s = _shortlist(tcp=["plain-strategy", {"strategy": "  "}, {"strategy": "ok:1"}])
    summary = shortlist_to_provider_summary(s)
    assert "plain-strategy" in summary["custom_strategies"]["tls12"]
    assert "ok:1" in summary["custom_strategies"]["tls12"]


# ── seed_state_db ─────────────────────────────────────────────────────


def test_seed_state_db_passes(tmp_path):
    db = MagicMock()
    db.log_tcp = AsyncMock()
    db.log_udp = AsyncMock()
    with patch("blockchecks.shortlist_import.open_run_store", return_value=db):
        db.init = AsyncMock()
        count = _run(seed_state_db(_shortlist(), "x.db"))
    assert count == 2  # 1 tcp + 1 udp
    db.log_tcp.assert_awaited_once()
    db.log_udp.assert_awaited_once()


def test_seed_state_db_mark_pass_false():
    assert _run(seed_state_db(_shortlist(), "x.db", mark_pass=False)) == 0


# ── import_shortlist (sync) ───────────────────────────────────────────


def test_import_shortlist_sync(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps(_shortlist()))
    out = tmp_path / "out"
    with patch("blockchecks.shortlist_import.write_shortlist_presets",
               return_value={"tls12": "x.txt"}):
        result = import_shortlist(p, out_dir=str(out))
    assert result["presets"] == {"tls12": "x.txt"}


def test_import_shortlist_seeds_db(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps(_shortlist()))
    db = MagicMock()
    db.log_tcp = AsyncMock()
    db.log_udp = AsyncMock()
    db.init = AsyncMock()
    with patch("blockchecks.shortlist_import.write_shortlist_presets",
               return_value={}), patch(
        "blockchecks.shortlist_import.open_run_store", return_value=db
    ):
        result = import_shortlist(p, db_path="x.db", seed_db=True)
    assert result["seeded_rows"] == 2


# ── import_shortlist_async ────────────────────────────────────────────


def test_import_shortlist_async(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps(_shortlist()))
    with patch("blockchecks.shortlist_import.write_shortlist_presets",
               return_value={}):
        result = _run(import_shortlist_async(p))
    assert result["schema"] == SCHEMA


# ── main ──────────────────────────────────────────────────────────────


def test_main_ok(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps(_shortlist()))
    with patch("blockchecks.shortlist_import.write_shortlist_presets",
               return_value={"tls12": "x"}):
        rc = main(["-i", str(p)])
    assert rc == 0


def _run(coro):
    import asyncio

    return asyncio.run(coro)
