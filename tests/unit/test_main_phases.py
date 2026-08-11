"""Unit tests for main_phases — bs full orchestrator helpers.

Covers the pure / orchestrator-level functions with mocked external deps.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.engine.config import DEFAULT_VOICE_IP
from blockchecks.main_phases import (
    FullRunContext,
    TcpProgress,
    apply_gp_protocol_flags,
    arm_run_deadline,
    build_async_runner,
    build_full_run_context,
    build_matrix_fingerprint,
    cap_strategy_count,
    cleanup_runner,
    configure_tcp_execution,
    discover_voice_endpoint,
    export_and_summarize,
    generate_strategy_items,
    load_run_domains,
    prepare_run_dns,
    print_full_run_banner,
    print_optional_phases_skip,
    print_settle_profile,
    resolve_settle_profile,
    run_http_phase,
    run_pairs_phase,
    run_preflight_filter,
    run_quic_phase,
    run_tcp_coverage_phase,
    split_sources,
)

pytestmark = pytest.mark.unit


def _args(**over):
    base = dict(
        domain="youtube.com",
        domains_file=None,
        allow_unsafe_domains=False,
        no_secure_dns=False,
        skip_dns_audit=False,
        allow_dns_hijack=False,
        doh_server=None,
        db=":memory:",
        db_batch=10,
        max=0,
        scan_level="fast",
        parallel=2,
        pair_max=200,
        discover_dns=5,
        discover_dns_no_bootstrap=False,
        quic_timeout=None,
        timeout=5.0,
        protocol="tls12",
        resume=False,
        tcp_only=False,
        no_http=False,
        no_quic=False,
        no_voice=False,
        http_off=False,
        http3_off=False,
        tls12_off=False,
        tls13_off=False,
        tcp_sources="standard,custom",
        udp_sources="custom",
        quic_sources="standard_quic",
        http_sources="custom,standard_http",
        adaptive=False,
        fan_out=False,
        curl_parallel=1,
        no_family_gates=False,
        no_adaptive_weights=False,
        adaptive_epsilon=0.1,
        no_wssize=True,
        disable_ech=False,
        no_settle_profile=True,
        settle_profile=None,
        lua_bridge=False,
        bridge_batch=500,
        lua_bridge_compare=False,
        lua_extra=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


# ── pure helpers ──────────────────────────────────────────────────────


def test_cap_strategy_count():
    assert cap_strategy_count(0) == 999_999
    assert cap_strategy_count(-5) == 999_999
    assert cap_strategy_count(10) == 10


def test_split_sources():
    assert split_sources("a,b,c") == ["a", "b", "c"]
    assert split_sources("a,,b") == ["a", "b"]
    assert split_sources("") == []


def test_apply_gp_protocol_flags():
    args = _args(http_off=True, http3_off=True)
    skip = apply_gp_protocol_flags(args)
    assert args.no_http is True and args.no_quic is True
    assert skip is False


def test_apply_gp_protocol_flags_skips_tcp():
    args = _args(tls12_off=True)
    assert apply_gp_protocol_flags(args) is True
    args2 = _args(tls13_off=True, protocol="tls13")
    assert apply_gp_protocol_flags(args2) is True


# ── load_run_domains ─────────────────────────────────────────────────


def test_load_run_domains_file_missing():
    args = _args(domains_file="/nonexistent/x.txt")
    with patch("blockchecks.main_phases.load_domains", side_effect=FileNotFoundError):
        domains, fname, rc = load_run_domains(args)
    assert rc == 1 and domains == []


def test_load_run_domains_empty():
    args = _args(domains_file="x.txt")
    loaded = MagicMock()
    loaded.domains = []
    loaded.skipped = []
    with patch("blockchecks.main_phases.load_domains", return_value=loaded):
        domains, _, rc = load_run_domains(args)
    assert rc == 1


def test_load_run_domains_ok():
    args = _args(domains_file="x.txt")
    loaded = MagicMock()
    loaded.domains = ["a.com", "b.com"]
    loaded.skipped = []
    with patch("blockchecks.main_phases.load_domains", return_value=loaded), patch(
        "blockchecks.main_phases.auto_enable_gv_ggc"
    ):
        domains, fname, rc = load_run_domains(args)
    assert rc is None
    assert domains == ["a.com", "b.com"]


# ── prepare_run_dns ───────────────────────────────────────────────────


def test_prepare_run_dns_rc():
    args = _args()
    with patch("blockchecks.main_phases.prepare_dns_for_run",
               return_value=(None, [], 7)), patch(
        "blockchecks.data_block.provider.provider_name"):
        cache, audits, rc = prepare_run_dns(args, ["a.com"])
    assert rc == 7


def test_prepare_run_dns_ok():
    args = _args()
    with patch("blockchecks.main_phases.prepare_dns_for_run",
               return_value=(MagicMock(), [MagicMock()], None)), patch(
        "blockchecks.data_block.provider.provider_name"):
        cache, audits, rc = prepare_run_dns(args, ["a.com"])
    assert rc is None and audits


# ── run_preflight_filter ──────────────────────────────────────────────


def test_run_preflight_filter_exit():
    args = _args()
    preflight = MagicMock()
    preflight.exit_code = 5
    preflight.error = "err"
    with patch("blockchecks.engine.preflight.run_preflight_async",
               new=AsyncMock(return_value=preflight)):
        domains, primary, rc = asyncio.run(run_preflight_filter(args, ["a.com"], "a.com", None))
    assert rc == 5


def test_run_preflight_filter_skip_all():
    args = _args()
    preflight = MagicMock()
    preflight.exit_code = None
    preflight.skip_domains = ["a.com"]
    with patch("blockchecks.engine.preflight.run_preflight_async",
               new=AsyncMock(return_value=preflight)):
        domains, primary, rc = asyncio.run(run_preflight_filter(args, ["a.com"], "a.com", None))
    assert rc == 0 and domains == []


def test_run_preflight_filter_partial_skip():
    args = _args()
    preflight = MagicMock()
    preflight.exit_code = None
    preflight.skip_domains = ["a.com"]
    with patch("blockchecks.engine.preflight.run_preflight_async",
               new=AsyncMock(return_value=preflight)):
        domains, primary, rc = asyncio.run(
            run_preflight_filter(args, ["a.com", "b.com"], "a.com", None)
        )
    assert rc is None
    assert domains == ["b.com"]
    assert primary == "b.com"


# ── build_full_run_context ────────────────────────────────────────────


def test_build_full_run_context():
    args = _args()
    with patch("blockchecks.main_phases.repeats_from_args",
               return_value=(1, False, "fast", False)):
        ctx = build_full_run_context(args, MagicMock(), ["a.com"], "f", None, [])
    assert isinstance(ctx, FullRunContext)
    assert ctx.primary == "youtube.com"
    assert ctx.tcp_sources == ["standard", "custom"]
    assert ctx.max_n == 999_999
    assert ctx.steps == 7


# ── print_full_run_banner ─────────────────────────────────────────────


def test_print_full_run_banner_smoke():
    args = _args()
    ctx = build_full_run_context(args, MagicMock(), ["a.com"], "f", None, [])
    print_full_run_banner(ctx)  # must not raise


# ── generate_strategy_items ───────────────────────────────────────────


def test_generate_strategy_items_no_tcp():
    args = _args()
    ctx = build_full_run_context(args, MagicMock(), ["a.com"], "f", None, [])
    gen = MagicMock()
    gen.generate_tcp = AsyncMock(return_value=[])
    gen.generate_udp = AsyncMock(return_value=[])
    gen.generate_quic = AsyncMock(return_value=[])
    gen.generate_http = AsyncMock(return_value=[])
    rc = asyncio.run(generate_strategy_items(ctx, gen))
    assert rc == 1


def test_generate_strategy_items_ok():
    args = _args()
    ctx = build_full_run_context(args, MagicMock(), ["a.com"], "f", None, [])
    gen = MagicMock()
    gen.generate_tcp = AsyncMock(return_value=[MagicMock()])
    gen.generate_udp = AsyncMock(return_value=[])
    gen.generate_quic = AsyncMock(return_value=[])
    gen.generate_http = AsyncMock(return_value=[])
    rc = asyncio.run(generate_strategy_items(ctx, gen))
    assert rc is None
    assert ctx.total_tcp_jobs == 1


def test_generate_strategy_items_tcp_only():
    args = _args(tcp_only=True)
    ctx = build_full_run_context(args, MagicMock(), ["a.com"], "f", None, [])
    gen = MagicMock()
    gen.generate_tcp = AsyncMock(return_value=[MagicMock()])
    gen.generate_http = AsyncMock(return_value=[])
    rc = asyncio.run(generate_strategy_items(ctx, gen))
    assert rc is None
    gen.generate_udp.assert_not_called()
    gen.generate_quic.assert_not_called()


# ── configure_tcp_execution ───────────────────────────────────────────


def test_configure_tcp_execution_classic():
    args = _args()
    ctx = build_full_run_context(args, MagicMock(), ["a.com"], "f", None, [])
    with patch("blockchecks.main_phases.fanout_allowed", return_value=(False, "")):
        configure_tcp_execution(ctx)
    assert ctx.use_adaptive is False
    assert ctx.use_fanout is False


def test_configure_tcp_execution_adaptive():
    args = _args(adaptive=True, curl_parallel=2)
    ctx = build_full_run_context(args, MagicMock(), ["a.com"], "f", None, [])
    with patch("blockchecks.main_phases.fanout_allowed", return_value=(False, "family")):
        configure_tcp_execution(ctx)
    assert ctx.use_adaptive is True


# ── settle profile / fingerprint ──────────────────────────────────────


def test_resolve_settle_profile_disabled():
    args = _args(no_settle_profile=True)
    assert resolve_settle_profile(args) is None


def test_resolve_settle_profile_explicit():
    args = _args(no_settle_profile=False, settle_profile="/tmp/x.json")
    with patch("blockchecks.main_phases.load_profile") as lp:
        resolve_settle_profile(args)
    lp.assert_called_once_with("/tmp/x.json")


def test_print_settle_profile_smoke():
    sp = MagicMock()
    sp.source_path = "/tmp/x.json"
    sp.defaults = None
    sp.strategies = [1, 2, 3]
    print_settle_profile(sp)


def test_build_matrix_fingerprint():
    args = _args()
    ctx = build_full_run_context(args, MagicMock(), ["a.com"], "f", None, [])
    with patch("blockchecks.main_phases.matrix_fingerprint", return_value="fp123"):
        fp = build_matrix_fingerprint(ctx)
    assert fp == "fp123"


# ── build_async_runner / arm_run_deadline ─────────────────────────────


def test_build_async_runner():
    args = _args()
    ctx = build_full_run_context(args, MagicMock(), ["a.com"], "f", None, [])
    with patch("blockchecks.main_phases.resolve_probe_backend", return_value="classic"), patch(
        "blockchecks.main_phases.AsyncTestRunner"
    ) as RunnerCls:
        build_async_runner(ctx)
    kwargs = RunnerCls.call_args.kwargs
    assert kwargs["pool_size"] == 2


def test_arm_run_deadline_no_budget():
    ctx = build_full_run_context(_args(max_timeh=None), MagicMock(), ["a.com"], "f", None, [])
    asyncio.run(arm_run_deadline(ctx))
    assert ctx.deadline is None


def test_arm_run_deadline_with_budget():
    args = _args()
    args.max_timem = 1
    ctx = build_full_run_context(args, MagicMock(), ["a.com"], "f", None, [])
    with patch("blockchecks.main_phases.RunDeadline.from_args") as from_args:
        d = MagicMock()
        d.start_background = AsyncMock()
        d.budget_label.return_value = "1m"
        from_args.return_value = d
        asyncio.run(arm_run_deadline(ctx))
    d.arm.assert_called_once()


# ── print_optional_phases_skip / TcpProgress ──────────────────────────


def test_print_optional_phases_skip_deadline():
    ctx = build_full_run_context(_args(), MagicMock(), ["a.com"], "f", None, [])
    d = MagicMock()
    d.triggered = True
    d.budget_label.return_value = "2m"
    ctx.deadline = d
    print_optional_phases_skip(ctx)


def test_tcp_progress_report(capsys):
    p = TcpProgress(total=10, done=50, passed=2, skipped=1)
    p.report()
    out = capsys.readouterr().out
    assert "[50/10]" in out or "pass=" in out


# ── async phases (mocked runner/db) ──────────────────────────────────


def _mk_ctx(**over):

    args = _args()
    args.out_dir = None
    ctx = build_full_run_context(args, MagicMock(), ["a.com"], "f", None, [])
    ctx.primary = "a.com"
    ctx.stop = asyncio.Event()
    ctx.runner = AsyncMock()
    ctx.db = MagicMock()
    ctx.fp = "fp"
    for k, v in over.items():
        setattr(ctx, k, v)
    return ctx


def test_tcp_coverage_phase_skips_no_items():
    ctx = _mk_ctx(tcp_items=[])
    asyncio.run(run_tcp_coverage_phase(ctx))


def test_tcp_coverage_phase_sequential():
    ctx = _mk_ctx()
    ctx.tcp_items = [MagicMock()]
    ctx.total_tcp_jobs = 1
    with patch("blockchecks.main_phases.warn_zero_pass_domains",
               new=AsyncMock(return_value=[])), patch(
        "blockchecks.main_phases.resolve_probe_backend", return_value="classic"):
        asyncio.run(run_tcp_coverage_phase(ctx))


def test_tcp_coverage_phase_adaptive():
    ctx = _mk_ctx(use_adaptive=True)
    ctx.tcp_items = [MagicMock()]
    with patch("blockchecks.main_phases._run_tcp_adaptive",
               new=AsyncMock()) as adaptive, patch(
        "blockchecks.main_phases.warn_zero_pass_domains",
        new=AsyncMock(return_value=[])):
        asyncio.run(run_tcp_coverage_phase(ctx))
    adaptive.assert_awaited_once()


def test_tcp_coverage_phase_family_gates():
    ctx = _mk_ctx(use_family_gates=True)
    ctx.tcp_items = [MagicMock()]
    with patch("blockchecks.main_phases._run_tcp_family_gates",
               new=AsyncMock()) as fg, patch(
        "blockchecks.main_phases.warn_zero_pass_domains",
        new=AsyncMock(return_value=[])):
        asyncio.run(run_tcp_coverage_phase(ctx))
    fg.assert_awaited_once()


def test_run_http_phase_skipped_when_no_http():
    ctx = _mk_ctx(http_items=[])
    ctx.args.no_http = False
    asyncio.run(run_http_phase(ctx))


def test_run_http_phase_runs_items():
    ctx = _mk_ctx(http_items=[MagicMock()])
    ctx.args.no_http = False
    ctx.runner.test_tcp = AsyncMock(return_value=MagicMock(success=True))
    asyncio.run(run_http_phase(ctx))
    ctx.runner.test_tcp.assert_awaited()


def test_discover_voice_endpoint_skipped_tcp_only():
    ctx = _mk_ctx()
    ctx.args.tcp_only = True
    ip, port = asyncio.run(discover_voice_endpoint(ctx))
    assert ip == DEFAULT_VOICE_IP


def test_discover_voice_endpoint_dns_fallback():
    ctx = _mk_ctx()
    with patch("blockchecks.checkers.voice_dns.discover_dns_alive",
               new=AsyncMock(side_effect=RuntimeError("down"))):
        ip, port = asyncio.run(discover_voice_endpoint(ctx))
    assert ip == DEFAULT_VOICE_IP


def test_discover_voice_endpoint_ok():
    ctx = _mk_ctx()
    with patch("blockchecks.checkers.voice_dns.discover_dns_alive",
               new=AsyncMock(return_value=[{"ip": "1.2.3.4", "port": 50004,
                                            "method": "x", "bootstrap": True}])):
        ip, port = asyncio.run(discover_voice_endpoint(ctx))
    assert ip == "1.2.3.4" and port == 50004


def test_run_quic_phase_skipped_no_quic():
    ctx = _mk_ctx(quic_items=[])
    ctx.args.tcp_only = False
    ctx.args.no_quic = True
    asyncio.run(run_quic_phase(ctx))


def test_run_quic_phase_no_http3_support():
    ctx = _mk_ctx(quic_items=[MagicMock()])
    ctx.args.tcp_only = False
    ctx.args.no_quic = False
    with patch("blockchecks.main_phases.supports_http3", return_value=False):
        asyncio.run(run_quic_phase(ctx))


def test_run_quic_phase_runs():
    ctx = _mk_ctx(quic_items=[MagicMock()])
    ctx.args.tcp_only = False
    ctx.args.no_quic = False
    ctx.runner.test_quic = AsyncMock(return_value=MagicMock(success=True))
    with patch("blockchecks.main_phases.supports_http3", return_value=True), patch(
        "blockchecks.main_phases.resolve_probe_backend", return_value="classic"):
        asyncio.run(run_quic_phase(ctx))
    ctx.runner.test_quic.assert_awaited()


def test_run_pairs_phase_skipped_tcp_only():
    ctx = _mk_ctx()
    ctx.args.tcp_only = True
    asyncio.run(run_pairs_phase(ctx, "1.2.3.4", 50004))


def test_run_pairs_phase_no_working_tcp():
    ctx = _mk_ctx(udp_items=[MagicMock()])
    ctx.args.tcp_only = False
    ctx.db.get_working_tcp_details = AsyncMock(return_value=[])
    ctx.db.get_best_by_coverage = AsyncMock(return_value=[])
    asyncio.run(run_pairs_phase(ctx, "1.2.3.4", 50004))


def test_cleanup_runner():
    ctx = _mk_ctx()
    ctx.deadline = AsyncMock()
    ctx.deadline.cancel = AsyncMock()
    ctx.runner = AsyncMock()
    with patch("blockchecks.main_phases.finalize_db_and_weights",
               new=AsyncMock()) as fin:
        asyncio.run(cleanup_runner(ctx))
    ctx.deadline.cancel.assert_awaited_once()
    ctx.runner.stop.assert_awaited_once()
    fin.assert_awaited_once()


def test_export_and_summarize():
    ctx = _mk_ctx()
    with patch("blockchecks.engine.run_finalize.maybe_write_best_config_data_block",
               new=AsyncMock()), patch(
        "blockchecks.engine.run_finalize.maybe_sync_data_block", new=AsyncMock()), patch(
        "blockchecks.main_phases.maybe_export_configs",
        new=AsyncMock(return_value=None)), patch(
        "blockchecks.main_phases.write_run_summary", return_value="/tmp/s.json"), patch(
        "blockchecks.engine.run_finalize.run_exit_code", return_value=0):
        rc = asyncio.run(export_and_summarize(ctx))
    assert rc == 0


def test_export_and_summarize_with_export():
    ctx = _mk_ctx()
    with patch("blockchecks.engine.run_finalize.maybe_write_best_config_data_block",
               new=AsyncMock()), patch(
        "blockchecks.engine.run_finalize.maybe_sync_data_block", new=AsyncMock()), patch(
        "blockchecks.main_phases.maybe_export_configs",
        new=AsyncMock(return_value={"keenetic": "k", "raw": "r", "user_list": "u"})), patch(
        "blockchecks.main_phases.write_run_summary", return_value="/tmp/s.json"), patch(
        "blockchecks.engine.run_finalize.run_exit_code", return_value=1):
        rc = asyncio.run(export_and_summarize(ctx))
    assert rc == 1


def test_print_aq_stop_metrics_no_result():
    from blockchecks.main_phases import print_aq_stop_metrics

    ctx = _mk_ctx()
    ctx.aq_result = None
    print_aq_stop_metrics(ctx)  # no-op


def test_step_number_helpers():
    from blockchecks.main_phases import _pair_step, _quic_step, _voice_step

    ctx7 = _mk_ctx()
    ctx7.steps = 7
    ctx6 = _mk_ctx()
    ctx6.steps = 6
    assert _voice_step(ctx7) == 4 and _voice_step(ctx6) == 3
    assert _quic_step(ctx7) == 5 and _quic_step(ctx6) == 4
    assert _pair_step(ctx7) == 6 and _pair_step(ctx6) == 5
