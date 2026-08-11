"""Unit tests for nfconf — strategy export to nfqws2 conf files."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.nfconf import collect_export_strategies, export_configs, main

pytestmark = pytest.mark.unit


def _store():
    s = MagicMock()
    s.flush = AsyncMock()
    s.close = AsyncMock()
    s.get_common_tcp = AsyncMock(return_value=[])
    s.get_best_by_coverage = AsyncMock(return_value=[])
    s.get_best_tcp = AsyncMock(return_value=[])
    s.get_working_tcp = AsyncMock(return_value=[])
    s.get_strategy_config = AsyncMock(return_value=None)
    s.get_best_pairs = AsyncMock(return_value=[])
    s.get_best_udp = AsyncMock(return_value=[])
    s.get_best_quic = AsyncMock(return_value=[])
    return s


# ── collect_export_strategies ─────────────────────────────────────────


def test_collect_common_tcp():
    db = _store()
    db.get_common_tcp = AsyncMock(return_value=[{"strategy": "fake:a"}])
    db.get_strategy_config = AsyncMock(return_value="fake:a:strategy=1")
    tcp, udp, quic = asyncio.run(
        collect_export_strategies(db, domain="d.com", limit=3, domains=["a.com", "b.com"])
    )
    assert tcp == ["fake:a:strategy=1"]
    db.get_best_tcp.assert_not_called()


def test_collect_coverage_fallback():
    db = _store()
    db.get_best_by_coverage = AsyncMock(return_value=[{"strategy": "fake:b"}])
    db.get_strategy_config = AsyncMock(return_value=None)
    tcp, _, _ = asyncio.run(
        collect_export_strategies(db, domain="d.com", limit=3, domains=["a.com", "b.com"])
    )
    assert tcp == ["fake:b"]


def test_collect_working_fallback():
    db = _store()
    db.get_working_tcp = AsyncMock(return_value=["fake:c"])
    tcp, _, _ = asyncio.run(
        collect_export_strategies(db, domain="d.com", limit=3, domains=None)
    )
    assert tcp == ["fake:c"]


def test_collect_udp_from_pairs():
    db = _store()
    db.get_best_pairs = AsyncMock(return_value=[{"udp": "fake:udp1"}])
    udp_strats = asyncio.run(collect_export_strategies(db, domain="d.com", limit=3))
    assert "fake:udp1" in udp_strats[1]


def test_collect_udp_fallback_default():
    db = _store()
    _, udp, _ = asyncio.run(collect_export_strategies(db, domain="d.com", limit=3))
    assert udp == ["fake:blob=discord_udp:repeats=6"]


def test_collect_quic_fallback_default():
    db = _store()
    _, _, quic = asyncio.run(collect_export_strategies(db, domain="d.com", limit=3))
    assert quic == ["fake:blob=quic_initial:repeats=11"]


# ── export_configs ────────────────────────────────────────────────────


def test_export_configs_writes_files(tmp_path, monkeypatch):
    out = str(tmp_path / "out")
    store = _store()
    store.get_best_tcp = AsyncMock(return_value=[{"strategy": "fake:blob=stun:repeats=6"}])
    store.get_best_quic = AsyncMock(return_value=[{"strategy": "fake:quic"}])
    monkeypatch.setattr("blockchecks.nfconf.DEFAULT_DOMAINS_FILE", str(tmp_path / "no-domains.txt"))
    res = asyncio.run(
        export_configs(
            store=store,
            domain="d.com",
            limit=2,
            out_dir=out,
            timestamp="20260811_000000",
            domains_file=str(tmp_path / "no-domains.txt"),
        )
    )
    assert res["keenetic"].endswith("nfqws2_20260811_000000.conf")
    import os

    assert os.path.exists(res["keenetic"])
    assert os.path.exists(res["raw"])
    assert os.path.exists(res["user_list"])


def test_export_configs_opens_store_by_path(tmp_path, monkeypatch):
    out = str(tmp_path / "out")
    db = _store()
    db.init = AsyncMock()
    with patch("blockchecks.nfconf.open_run_store", return_value=db) as open_store:
        asyncio.run(
            export_configs(
                db_path="x.db",
                domain="d.com",
                limit=1,
                out_dir=out,
                domains_file=str(tmp_path / "no-domains.txt"),
            )
        )
    open_store.assert_called_once_with("x.db")
    db.init.assert_awaited_once()
    db.close.assert_awaited_once()


def test_export_configs_uses_domain_file_domains(tmp_path):
    doms = tmp_path / "domains.txt"
    doms.write_text("a.com\nb.com\n")
    out = tmp_path / "out"
    store = _store()
    store.get_best_tcp = AsyncMock(return_value=[{"strategy": "fake:a"}])
    store.get_working_tcp = AsyncMock(return_value=[])
    with patch("blockchecks.nfconf.build_raw_conf") as raw:
        raw.return_value = "raw"
        asyncio.run(
            export_configs(
                store=store, domain="d.com", limit=1, out_dir=str(out),
                domains_file=str(doms),
            )
        )
    # build_raw_conf received domains list from file
    assert raw.call_args.kwargs["domains"] == ["a.com", "b.com"]


def test_main_returns_zero(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["nfconf", "--limit", "1"])
    with patch("blockchecks.nfconf.export_configs", new=AsyncMock(
        return_value={
            "keenetic": "k", "raw": "r", "user_list": "u",
            "tcp": ["a"], "udp": ["b"], "quic": ["c"],
        }
    )):
        rc = main(["--limit", "1"])
    assert rc == 0
