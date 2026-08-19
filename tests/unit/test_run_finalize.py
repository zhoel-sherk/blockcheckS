"""Unit tests for run_finalize — export/summary/finalization helpers."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.engine.run_deadline import RunDeadline
from blockchecks.engine.run_finalize import (
    finalize_db_and_weights,
    maybe_export_configs,
    maybe_sync_data_block,
    maybe_write_best_config_data_block,
    rank_pass_strategies_for_export,
    run_exit_code,
    should_export,
    write_run_summary,
)

pytestmark = pytest.mark.unit


def _args(**over):
    base = dict(
        no_export_on_stop=False,
        out_dir="logs",
        export_limit=3,
        isp_interface="eth3",
        prefix="/opt/etc/nfqws2",
        mode="auto",
        no_common_only=False,
        data_block_sync=False,
    )
    base.update(over)
    return SimpleNamespace(**base)


# ── should_export ─────────────────────────────────────────────────────


def test_should_export_ok():
    assert should_export(_args(), stop_set=False, _deadline=None, pass_count=3) is True


def test_should_export_no_out_dir():
    assert should_export(_args(out_dir=None), stop_set=False, _deadline=None, pass_count=3) is False


def test_should_export_no_export_on_stop():
    assert (
        should_export(_args(no_export_on_stop=True), stop_set=True, _deadline=None, pass_count=3)
        is False
    )


def test_should_export_stop_no_passes():
    assert should_export(_args(), stop_set=True, _deadline=None, pass_count=0) is False


def test_should_export_stop_with_passes():
    assert should_export(_args(), stop_set=True, _deadline=None, pass_count=2) is True


# ── run_exit_code ─────────────────────────────────────────────────────


def test_run_exit_code_signal():
    assert run_exit_code(True, None, True) == 130


def test_run_exit_code_deadline_triggered_overrides_signal():
    ev = asyncio.Event()
    d = RunDeadline(ev, budget_sec=1.0)
    d.triggered = True
    assert run_exit_code(True, d, True) == 0


def test_run_exit_code_ok():
    assert run_exit_code(False, None, False) == 0


# ── write_run_summary ─────────────────────────────────────────────────


def test_write_run_summary(tmp_path):
    out = str(tmp_path / "out")
    path = write_run_summary(out, {"command": "scan", "passed": 3})
    assert Path(path).is_file()
    assert '"command": "scan"' in Path(path).read_text()


def test_write_run_summary_none_dir(tmp_path, monkeypatch):
    import blockchecks.engine.run_finalize as rf

    fake = tmp_path / "logs"
    monkeypatch.setattr(rf, "RUNTIME_LOGS_DIR", fake)
    path = write_run_summary(None, {"a": 1})
    assert Path(path).is_file()


# ── finalize_db_and_weights ───────────────────────────────────────────


def test_finalize_db_and_weights_no_weights():
    store = MagicMock()
    store.flush = AsyncMock()
    asyncio.run(finalize_db_and_weights(store, save_weights=True))
    store.flush.assert_awaited_once()


def test_finalize_db_and_weights_saves():
    store = MagicMock()
    store.flush = AsyncMock()
    with patch(
        "blockchecks.engine.run_finalize.persist_adaptive_weights", new=AsyncMock()
    ) as persist:
        asyncio.run(finalize_db_and_weights(store, aq_weights={"w": 1}, save_weights=True))
    persist.assert_awaited_once()


def test_finalize_db_and_weights_skips_save():
    store = MagicMock()
    store.flush = AsyncMock()
    with patch(
        "blockchecks.engine.run_finalize.persist_adaptive_weights", new=AsyncMock()
    ) as persist:
        asyncio.run(finalize_db_and_weights(store, aq_weights={"w": 1}, save_weights=False))
    persist.assert_not_called()


# ── maybe_export_configs ──────────────────────────────────────────────


def test_maybe_export_configs_skipped_when_no_passes():
    store = MagicMock()
    store.flush = AsyncMock()
    store.count_tcp_passes = AsyncMock(return_value=0)
    with patch("blockchecks.engine.run_finalize.export_configs", new=AsyncMock()) as exp:
        res = asyncio.run(
            maybe_export_configs(
                store, _args(), primary="x.com", domains_file=None, stop_set=True, deadline=None
            )
        )
    assert res is None
    exp.assert_not_called()


def test_maybe_export_configs_calls_export():
    store = MagicMock()
    store.flush = AsyncMock()
    store.count_tcp_passes = AsyncMock(return_value=5)
    with patch(
        "blockchecks.engine.run_finalize.export_configs",
        new=AsyncMock(return_value={"keenetic": "cfg", "raw": "r", "user_list": "u"}),
    ) as exp:
        res = asyncio.run(
            maybe_export_configs(
                store, _args(), primary="x.com", domains_file=None, stop_set=False, deadline=None
            )
        )
    assert res == {"keenetic": "cfg", "raw": "r", "user_list": "u"}
    exp.assert_awaited_once()


# ── data_block best-config / sync ─────────────────────────────────────


def test_maybe_write_best_config_data_block_no_db(tmp_path):
    with (
        patch(
            "blockchecks.data_block.provider.get_provider_dir",
            return_value=tmp_path,
        ),
        patch("blockchecks.data_block.store.ProviderStore") as StoreCls,
    ):
        store = StoreCls.return_value
        store.strategies_db = MagicMock()
        store.strategies_db.is_file.return_value = False
        asyncio.run(maybe_write_best_config_data_block())
        store.write_best_config.assert_not_called()


def test_maybe_write_best_config_data_block_writes(tmp_path):
    with (
        patch(
            "blockchecks.data_block.provider.get_provider_dir",
            return_value=tmp_path,
        ),
        patch("blockchecks.data_block.store.ProviderStore") as StoreCls,
        patch(
            "blockchecks.engine.conf_builder.build_keenetic_conf", return_value="[ipset]\n"
        ) as build,
    ):
        store = StoreCls.return_value
        store.strategies_db = MagicMock()
        store.strategies_db.is_file.return_value = True
        store.pass_strategies = AsyncMock(
            return_value=[
                {"strategy": "slow_tcp", "protocol": "tcp", "latency_ms": 200},
                {"strategy": "fast_tcp", "protocol": "tcp", "latency_ms": 50},
                {"strategy": "fake:blob=stun:repeats=6", "protocol": "udp", "latency_ms": 10},
                {
                    "strategy": "fake:blob=discord_udp:repeats=6",
                    "protocol": "udp",
                    "latency_ms": 40,
                },
            ]
        )
        asyncio.run(maybe_write_best_config_data_block())
        build.assert_called_once()
        kwargs = build.call_args.kwargs
        assert kwargs["tcp_strategies"][0] == "fast_tcp"
        assert kwargs["udp_strategies"][0] == "fake:blob=discord_udp:repeats=6"
        store.write_best_config.assert_called_once_with("[ipset]\n")


def test_rank_pass_strategies_for_export_latency_and_discord_udp():
    rows = [
        {"strategy": "tcp_b", "protocol": "tcp", "latency_ms": 90},
        {"strategy": "tcp_a", "protocol": "tcp", "latency_ms": 20},
        {"strategy": "fake:blob=stun:repeats=6", "protocol": "udp", "latency_ms": 5},
        {"strategy": "fake:blob=discord_udp:repeats=6", "protocol": "udp", "latency_ms": 80},
        {"strategy": "tcp_a", "protocol": "tcp", "latency_ms": 15},
    ]
    tcp, udp = rank_pass_strategies_for_export(rows, tcp_n=5, udp_n=5)
    assert tcp[0] == "tcp_a"
    assert udp[0] == "fake:blob=discord_udp:repeats=6"
    assert "fake:blob=stun:repeats=6" in udp


def test_maybe_sync_data_block_disabled():
    with patch("blockchecks.data_block.provider.get_provider_dir") as gpd:
        asyncio.run(maybe_sync_data_block(_args(data_block_sync=False)))
    gpd.assert_not_called()


def test_maybe_sync_data_block_enabled():
    with (
        patch("blockchecks.data_block.provider.get_provider_dir", return_value=MagicMock()),
        patch("blockchecks.data_block.store.ProviderStore") as StoreCls,
    ):
        store = StoreCls.return_value
        store.sync_commit = MagicMock()
        asyncio.run(maybe_sync_data_block(_args(data_block_sync=True)))
        store.sync_commit.assert_called_once_with(push=True)
