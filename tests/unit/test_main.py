"""Unit tests for main.py — bs full orchestrator dispatch + campaign flow."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.main import _run_full_campaign, build_arg_parser, main

pytestmark = pytest.mark.unit


def _args(**over):
    base = dict(
        db=":memory:",
        db_batch=10,
        domain="youtube.com",
        domains_file=None,
        allow_unsafe_domains=False,
        max_timeh=None,
        max_timem=None,
        scan_level="full",
        max=10,
        parallel=2,
        timeout=5.0,
        udp_timeout=3.0,
        protocol="tls12",
        resume=False,
        tcp_only=False,
        out_dir=None,
        no_export_on_stop=False,
        export_limit=3,
        isp_interface="eth3",
        prefix="/opt/etc/nfqws2",
        mode="auto",
        no_common_only=False,
        data_block_sync=False,
        settle_profile=None,
        no_settle_profile=True,
        tcp_sources="standard,custom",
        udp_sources="custom",
        quic_sources="standard_quic",
        http_sources="custom",
        no_http=False,
        no_quic=False,
        no_voice=False,
        discover_dns=5,
        discover_dns_no_bootstrap=False,
        pair_max=200,
        adaptive=False,
        fan_out=False,
        curl_parallel=1,
        no_family_gates=False,
        no_adaptive_weights=False,
        adaptive_epsilon=0.1,
        no_wssize=True,
        disable_ech=False,
        no_secure_dns=False,
        skip_dns_audit=False,
        allow_dns_hijack=False,
        doh_server=None,
        lua_bridge=False,
        bridge_batch=500,
        lua_bridge_compare=False,
        lua_extra=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _ctx():
    ctx = MagicMock()
    ctx.stop = asyncio.Event()
    ctx.runner = AsyncMock()
    ctx.db = MagicMock()
    return ctx


# ── _run_full_campaign ────────────────────────────────────────────────


def test_campaign_domains_error():
    args = _args()
    with patch("blockchecks.main.open_full_run_db", new=AsyncMock()) as db_open, patch(
        "blockchecks.main.load_run_domains", return_value=([], "f", 4)
    ):
        rc = asyncio.run(_run_full_campaign(args))
    assert rc == 4
    db_open.assert_awaited_once()


def test_campaign_dns_error():
    args = _args()
    with patch("blockchecks.main.open_full_run_db", new=AsyncMock()), patch(
        "blockchecks.main.load_run_domains", return_value=(["a.com"], None, None)
    ), patch("blockchecks.main.prepare_run_dns", return_value=(None, [], 5)):
        rc = asyncio.run(_run_full_campaign(args))
    assert rc == 5


def test_campaign_preflight_error():
    args = _args()
    with patch("blockchecks.main.open_full_run_db", new=AsyncMock()), patch(
        "blockchecks.main.load_run_domains", return_value=(["a.com"], None, None)
    ), patch("blockchecks.main.prepare_run_dns", return_value=(MagicMock(), [], None)), patch(
        "blockchecks.main.run_preflight_filter",
        new=AsyncMock(return_value=(["a.com"], "a.com", 6)),
    ):
        rc = asyncio.run(_run_full_campaign(args))
    assert rc == 6


def test_campaign_generate_error():
    args = _args()
    with patch("blockchecks.main.open_full_run_db", new=AsyncMock()), patch(
        "blockchecks.main.load_run_domains", return_value=(["a.com"], None, None)
    ), patch("blockchecks.main.prepare_run_dns", return_value=(MagicMock(), [], None)), patch(
        "blockchecks.main.run_preflight_filter",
        new=AsyncMock(return_value=(["a.com"], "a.com", None)),
    ), patch("blockchecks.main.build_full_run_context", return_value=_ctx()), patch(
        "blockchecks.main.generate_strategy_items", new=AsyncMock(return_value=8)
    ):
        rc = asyncio.run(_run_full_campaign(args))
    assert rc == 8


def test_campaign_full_success():
    args = _args()
    ctx = _ctx()
    with patch("blockchecks.main.open_full_run_db", new=AsyncMock()) as db_open, patch(
        "blockchecks.main.load_run_domains", return_value=(["a.com"], None, None)
    ), patch("blockchecks.main.prepare_run_dns", return_value=(MagicMock(), [], None)), patch(
        "blockchecks.main.run_preflight_filter",
        new=AsyncMock(return_value=(["a.com"], "a.com", None)),
    ), patch("blockchecks.main.build_full_run_context", return_value=ctx), patch(
        "blockchecks.main.generate_strategy_items", new=AsyncMock(return_value=None)
    ), patch("blockchecks.main.configure_tcp_execution"), patch(
        "blockchecks.main.resolve_settle_profile", return_value=None
    ), patch("blockchecks.main.print_settle_profile"), patch(
        "blockchecks.main.build_matrix_fingerprint", return_value="fp"
    ), patch("blockchecks.main.build_async_runner", return_value=ctx.runner), patch(
        "blockchecks.main.arm_stop_handlers"
    ), patch("blockchecks.main.arm_run_deadline", new=AsyncMock()), patch(
        "blockchecks.main.run_tcp_coverage_phase", new=AsyncMock()
    ), patch("blockchecks.main.run_http_phase", new=AsyncMock()), patch(
        "blockchecks.main.discover_voice_endpoint",
        new=AsyncMock(return_value=("1.2.3.4", 50004)),
    ), patch("blockchecks.main.run_quic_phase", new=AsyncMock()), patch(
        "blockchecks.main.run_pairs_phase", new=AsyncMock()
    ), patch("blockchecks.main.cleanup_runner", new=AsyncMock()) as cleanup, patch(
        "blockchecks.main.export_and_summarize", new=AsyncMock(return_value=0)
    ):
        rc = asyncio.run(_run_full_campaign(args))
    assert rc == 0
    ctx.runner.start.assert_awaited_once()
    cleanup.assert_awaited_once()
    db_open.assert_awaited_once()


# ── build_arg_parser / main ───────────────────────────────────────────


def test_build_arg_parser_smoke():
    p = build_arg_parser()
    assert p.prog == "bs full"
    ns = p.parse_args(["-d", "youtube.com", "--tcp-only"])
    assert ns.domain == "youtube.com"
    assert ns.tcp_only is True


def test_main_dispatches_and_returns_code():
    with patch("blockchecks.engine.paths.apply_pycache_prefix"), patch(
        "blockchecks.engine.paths.ensure_dirs"
    ), patch("blockchecks.cli.user_config.load_user_config", return_value={}), patch(
        "blockchecks.engine.paths.migrate_legacy_state_db"
    ), patch("blockchecks.cli.user_config.finalize_store_args"), patch(
        "blockchecks.main.validate_time_limit_args"
    ), patch(
        "blockchecks.main.ensure_system_deps_or_exit", return_value=0
    ), patch("blockchecks.main.run_full", new=AsyncMock(return_value=3)) as rf:
        code = main(["-d", "youtube.com", "--skip-deps-check"])
    assert code == 3
    rf.assert_awaited_once()


def test_main_deps_error_short_circuits():
    with patch("blockchecks.engine.paths.apply_pycache_prefix"), patch(
        "blockchecks.engine.paths.ensure_dirs"
    ), patch("blockchecks.cli.user_config.load_user_config", return_value={}), patch(
        "blockchecks.engine.paths.migrate_legacy_state_db"
    ), patch("blockchecks.cli.user_config.finalize_store_args"), patch(
        "blockchecks.main.validate_time_limit_args"
    ), patch(
        "blockchecks.main.ensure_system_deps_or_exit", return_value=4
    ), patch("blockchecks.main.run_full", new=AsyncMock()) as rf:
        code = main(["-d", "youtube.com", "--skip-deps-check"])
    assert code == 4
    rf.assert_not_called()
