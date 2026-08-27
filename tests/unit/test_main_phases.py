"""Unit tests for main_phases — bs full orchestrator helpers.

Covers the pure / orchestrator-level functions with mocked external deps.
"""

from __future__ import annotations

import asyncio
import signal
import warnings
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
    open_full_run_db,
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


@pytest.fixture
def fail_store():
    """Store whose init() fails (QA-5)."""
    db = MagicMock()
    db.init = AsyncMock(side_effect=OSError("store unavailable"))
    return db


@pytest.fixture
def timeout_budget_args():
    """Invalid wall-clock budget for arm_run_deadline (QA-5)."""
    args = _args()
    args.max_timem = 0
    return args


def _args(**over):
    base = dict(
        domain="youtube.com",
        domains_file=None,
        preset=None,
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
    with (
        patch("blockchecks.main_phases.load_domains", return_value=loaded),
        patch("blockchecks.main_phases.auto_enable_gv_ggc"),
    ):
        domains, fname, rc = load_run_domains(args)
    assert rc is None
    assert domains == ["a.com", "b.com"]


def test_load_run_domains_dash_d_skips_default_file():
    args = _args(domain="discord.com", domains_file=None)
    with patch("blockchecks.main_phases.load_domains") as load:
        domains, fname, rc = load_run_domains(args)
    load.assert_not_called()
    assert rc is None
    assert domains == ["discord.com"]
    assert fname == "discord.com"


def test_load_run_domains_file_wins_over_dash_d():
    args = _args(domain="discord.com", domains_file="x.txt")
    loaded = MagicMock()
    loaded.domains = ["a.com"]
    loaded.skipped = []
    with (
        patch("blockchecks.main_phases.load_domains", return_value=loaded),
        patch("blockchecks.main_phases.auto_enable_gv_ggc"),
    ):
        domains, fname, rc = load_run_domains(args)
    assert rc is None
    assert domains == ["a.com"]
    assert fname == "x.txt"


def test_load_run_domains_preset():
    args = _args(domain="", domains_file=None, preset="discord")
    loaded = MagicMock()
    loaded.domains = ["discord.com", "updates.discord.com"]
    loaded.skipped = []
    loaded.source = "presets/domains/discord.txt"
    with (
        patch("blockchecks.main_phases.load_preset", return_value=loaded),
        patch("blockchecks.main_phases.auto_enable_gv_ggc"),
    ):
        domains, fname, rc = load_run_domains(args)
    assert rc is None
    assert domains == ["discord.com", "updates.discord.com"]
    assert fname.endswith("discord.txt")


def test_load_run_domains_file_wins_over_preset():
    args = _args(preset="discord", domains_file="x.txt", domain="")
    loaded = MagicMock()
    loaded.domains = ["a.com"]
    loaded.skipped = []
    with (
        patch("blockchecks.main_phases.load_domains", return_value=loaded),
        patch("blockchecks.main_phases.auto_enable_gv_ggc"),
    ):
        domains, fname, rc = load_run_domains(args)
    assert rc is None
    assert domains == ["a.com"]
    assert fname == "x.txt"


def test_load_run_domains_preset_missing():
    args = _args(domain="", domains_file=None, preset="nope")
    with patch("blockchecks.main_phases.load_preset", side_effect=FileNotFoundError):
        domains, fname, rc = load_run_domains(args)
    assert rc == 1 and domains == []
    assert fname == "nope"


def test_load_run_domains_default_missing_when_no_dash_d():
    """No -d / preset / file: missing default coverage list is a hard FAIL."""
    args = _args(domain="", domains_file=None, preset=None)
    with patch("blockchecks.main_phases.load_domains", side_effect=FileNotFoundError):
        domains, fname, rc = load_run_domains(args)
    assert rc == 1 and domains == []
    assert fname


def test_build_full_run_context_empty_domains_raises():
    args = _args(domain="")
    with pytest.raises(IndexError):
        build_full_run_context(args, MagicMock(), [], "f", None, [])


def test_open_full_run_db_store_error(fail_store):
    with patch("blockchecks.main_phases.open_run_store", return_value=fail_store):
        with pytest.raises(OSError, match="store unavailable"):
            asyncio.run(open_full_run_db(_args()))


def test_arm_run_deadline_nonpositive_budget(timeout_budget_args):
    ctx = build_full_run_context(timeout_budget_args, MagicMock(), ["a.com"], "f", None, [])
    with pytest.raises(SystemExit, match="positive"):
        asyncio.run(arm_run_deadline(ctx))


# ── prepare_run_dns ───────────────────────────────────────────────────


def test_prepare_run_dns_rc():
    args = _args()
    with (
        patch("blockchecks.main_phases.prepare_dns_for_run", return_value=(None, [], 7)),
        patch("blockchecks.data_block.provider.provider_name", return_value="testp"),
    ):
        cache, audits, rc = prepare_run_dns(args, ["a.com"])
    assert rc == 7


def test_prepare_run_dns_ok():
    args = _args()
    with (
        patch(
            "blockchecks.main_phases.prepare_dns_for_run",
            return_value=(MagicMock(), [MagicMock()], None),
        ),
        patch("blockchecks.data_block.provider.provider_name", return_value="testp"),
    ):
        cache, audits, rc = prepare_run_dns(args, ["a.com"])
    assert rc is None and audits


# ── run_preflight_filter ──────────────────────────────────────────────


def test_run_preflight_filter_exit():
    args = _args()
    preflight = MagicMock()
    preflight.exit_code = 5
    preflight.error = "err"
    with patch(
        "blockchecks.engine.preflight.run_preflight_async", new=AsyncMock(return_value=preflight)
    ):
        domains, primary, rc = asyncio.run(run_preflight_filter(args, ["a.com"], "a.com", None))
    assert rc == 5


def test_run_preflight_filter_skip_all():
    args = _args()
    preflight = MagicMock()
    preflight.exit_code = None
    preflight.skip_domains = ["a.com"]
    with patch(
        "blockchecks.engine.preflight.run_preflight_async", new=AsyncMock(return_value=preflight)
    ):
        domains, primary, rc = asyncio.run(run_preflight_filter(args, ["a.com"], "a.com", None))
    assert rc == 0 and domains == []


def test_run_preflight_filter_partial_skip():
    args = _args()
    preflight = MagicMock()
    preflight.exit_code = None
    preflight.skip_domains = ["a.com"]
    with patch(
        "blockchecks.engine.preflight.run_preflight_async", new=AsyncMock(return_value=preflight)
    ):
        domains, primary, rc = asyncio.run(
            run_preflight_filter(args, ["a.com", "b.com"], "a.com", None)
        )
    assert rc is None
    assert domains == ["b.com"]
    assert primary == "b.com"


# ── build_full_run_context ────────────────────────────────────────────


def test_build_full_run_context():
    args = _args()
    with patch("blockchecks.main_phases.repeats_from_args", return_value=(1, False, "fast", False)):
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


def test_generate_strategy_items_no_voice():
    args = _args(no_voice=True)
    ctx = build_full_run_context(args, MagicMock(), ["a.com"], "f", None, [])
    gen = MagicMock()
    gen.generate_tcp = AsyncMock(return_value=[MagicMock()])
    gen.generate_http = AsyncMock(return_value=[])
    gen.generate_quic = AsyncMock(return_value=[])
    rc = asyncio.run(generate_strategy_items(ctx, gen))
    assert rc is None
    gen.generate_udp.assert_not_called()


# ── configure_tcp_execution ───────────────────────────────────────────


def test_configure_tcp_execution_classic():
    args = _args(no_adaptive=True)
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
    with (
        patch("blockchecks.main_phases.resolve_probe_backend", return_value="lua_bridge"),
        patch("blockchecks.main_phases.AsyncTestRunner") as RunnerCls,
    ):
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


def test_tcp_progress_report(caplog):
    p = TcpProgress(total=10, done=50, passed=2, skipped=1)
    with caplog.at_level("INFO", logger="blockchecks"):
        p.report()
    assert "[50/10]" in caplog.text or "pass=" in caplog.text


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
    with (
        patch("blockchecks.main_phases.warn_zero_pass_domains", new=AsyncMock(return_value=[])),
        patch("blockchecks.main_phases._run_tcp_sequential_bridge", new=AsyncMock()),
    ):
        asyncio.run(run_tcp_coverage_phase(ctx))


def test_tcp_coverage_phase_adaptive():
    ctx = _mk_ctx(use_adaptive=True)
    ctx.tcp_items = [MagicMock()]
    with (
        patch("blockchecks.main_phases._run_tcp_adaptive", new=AsyncMock()) as adaptive,
        patch("blockchecks.main_phases.warn_zero_pass_domains", new=AsyncMock(return_value=[])),
    ):
        asyncio.run(run_tcp_coverage_phase(ctx))
    adaptive.assert_awaited_once()


def test_tcp_coverage_phase_family_gates():
    ctx = _mk_ctx(use_family_gates=True)
    ctx.tcp_items = [MagicMock()]
    with (
        patch("blockchecks.main_phases._run_tcp_family_gates", new=AsyncMock()) as fg,
        patch("blockchecks.main_phases.warn_zero_pass_domains", new=AsyncMock(return_value=[])),
    ):
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
    with patch(
        "blockchecks.checkers.voice_dns.discover_dns_alive",
        new=AsyncMock(side_effect=RuntimeError("down")),
    ):
        ip, port = asyncio.run(discover_voice_endpoint(ctx))
    assert ip == DEFAULT_VOICE_IP


def test_discover_voice_endpoint_ok():
    ctx = _mk_ctx()
    with patch(
        "blockchecks.checkers.voice_dns.discover_dns_alive",
        new=AsyncMock(
            return_value=[{"ip": "1.2.3.4", "port": 50004, "method": "x", "bootstrap": True}]
        ),
    ):
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
    ctx.runner._run_probe_batch = AsyncMock(return_value=[MagicMock(success=True)])
    with (
        patch("blockchecks.main_phases.supports_http3", return_value=True),
    ):
        asyncio.run(run_quic_phase(ctx))
    ctx.runner._run_probe_batch.assert_awaited()


def test_run_pairs_phase_skipped_tcp_only():
    ctx = _mk_ctx()
    ctx.args.tcp_only = True
    asyncio.run(run_pairs_phase(ctx, "1.2.3.4", 50004))


def test_run_pairs_phase_skipped_no_voice():
    ctx = _mk_ctx(udp_items=[MagicMock()])
    ctx.args.tcp_only = False
    ctx.args.no_voice = True
    ctx.runner.test_pair_matrix = AsyncMock()
    asyncio.run(run_pairs_phase(ctx, "1.2.3.4", 50004))
    ctx.runner.test_pair_matrix.assert_not_called()


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
    with patch("blockchecks.main_phases.finalize_db_and_weights", new=AsyncMock()) as fin:
        asyncio.run(cleanup_runner(ctx))
    ctx.deadline.cancel.assert_awaited_once()
    ctx.runner.stop.assert_awaited_once()
    fin.assert_awaited_once()


def test_export_and_summarize():
    ctx = _mk_ctx()
    with (
        patch(
            "blockchecks.engine.run_finalize.maybe_write_best_config_data_block", new=AsyncMock()
        ),
        patch("blockchecks.engine.run_finalize.maybe_sync_data_block", new=AsyncMock()),
        patch("blockchecks.main_phases.maybe_export_configs", new=AsyncMock(return_value=None)),
        patch("blockchecks.main_phases.write_run_summary", return_value="/tmp/s.json"),
        patch("blockchecks.engine.run_finalize.run_exit_code", return_value=0),
    ):
        rc = asyncio.run(export_and_summarize(ctx))
    assert rc == 0


def test_export_and_summarize_with_export():
    ctx = _mk_ctx()
    with (
        patch(
            "blockchecks.engine.run_finalize.maybe_write_best_config_data_block", new=AsyncMock()
        ),
        patch("blockchecks.engine.run_finalize.maybe_sync_data_block", new=AsyncMock()),
        patch(
            "blockchecks.main_phases.maybe_export_configs",
            new=AsyncMock(return_value={"keenetic": "k", "raw": "r", "user_list": "u"}),
        ),
        patch("blockchecks.main_phases.write_run_summary", return_value="/tmp/s.json"),
        patch("blockchecks.engine.run_finalize.run_exit_code", return_value=1),
    ):
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


# ── arm_stop_handlers / _run_tcp_sequential ───────────────────────────


def test_arm_stop_handlers_registers():
    from blockchecks.main_phases import arm_stop_handlers

    ctx = _mk_ctx()
    loop = MagicMock()
    with patch("blockchecks.main_phases.asyncio.get_running_loop", return_value=loop):
        restore = arm_stop_handlers(ctx)
    assert loop.add_signal_handler.call_count == 3
    restore()
    assert loop.remove_signal_handler.call_count == 3


def test_arm_stop_handlers_signal_fallback(monkeypatch):
    from blockchecks.main_phases import arm_stop_handlers

    ctx = _mk_ctx()
    seen: list[int] = []

    def _raise(*a, **k):
        raise NotImplementedError

    def _sig(sig, handler):
        seen.append(sig)
        return signal.SIG_DFL

    loop = MagicMock()
    loop.add_signal_handler.side_effect = _raise
    monkeypatch.setattr("blockchecks.main_phases.signal.signal", _sig)
    with patch("blockchecks.main_phases.asyncio.get_running_loop", return_value=loop):
        restore = arm_stop_handlers(ctx)
    assert signal.SIGINT in seen
    assert signal.SIGTERM in seen
    restore()


def test_tcp_sequential_runs_jobs():
    from blockchecks.main_phases import _run_tcp_sequential

    ctx = _mk_ctx()
    ctx.tcp_items = [MagicMock()]
    progress = MagicMock()
    with patch("blockchecks.main_phases._run_tcp_sequential_bridge", new=AsyncMock()) as br:
        asyncio.run(_run_tcp_sequential(ctx, progress))
    br.assert_awaited()


def test_tcp_sequential_stop_event():
    from blockchecks.main_phases import _run_tcp_sequential

    ctx = _mk_ctx()
    ctx.tcp_items = [MagicMock()]
    ctx.stop.set()
    progress = MagicMock()
    with patch("blockchecks.main_phases._run_tcp_sequential_bridge", new=AsyncMock()):
        asyncio.run(_run_tcp_sequential(ctx, progress))
    ctx.runner.test_tcp.assert_not_awaited()


def test_tcp_sequential_stop_does_not_leak_coroutines():
    from blockchecks.main_phases import _run_tcp_sequential

    ctx = _mk_ctx()
    ctx.tcp_items = [MagicMock() for _ in range(250)]
    ctx.domains = ["a.com", "b.com"]
    ctx.stop.set()
    progress = MagicMock()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with patch("blockchecks.main_phases._run_tcp_sequential_bridge", new=AsyncMock()):
            asyncio.run(_run_tcp_sequential(ctx, progress))
    assert not any("never awaited" in str(w.message) for w in caught)


# ── _run_tcp_adaptive / family_gates / fanout / run_pairs_phase ───────


def test_tcp_adaptive():
    from blockchecks.main_phases import _run_tcp_adaptive

    ctx = _mk_ctx()
    ctx.tcp_items = [MagicMock()]
    ctx.domains = ["a.com"]
    ctx.db = MagicMock()
    ctx.args.resume = False
    ctx.args.adaptive_epsilon = 0.1
    ctx.args.no_adaptive_weights = False
    ctx.args.timeout = 5.0
    ctx.args.protocol = "tls12"
    ctx.args.parallel = 2
    ctx.args.disable_ech = False
    aq = MagicMock()
    aq.done = 1
    aq.passed = 1
    aq.weights = {}
    aq.metrics = MagicMock()
    aq.metrics.time_to_first_pass = 1.0
    aq.metrics.fanout_enqueued = 0
    aq.metrics.half_mark_jobs = False
    progress = SimpleNamespace(done=0, skipped=0, passed=0, report=lambda: None)
    with (
        patch(
            "blockchecks.main_phases.build_adaptive_queue",
            new=AsyncMock(return_value=([MagicMock()], 0)),
        ),
        patch(
            "blockchecks.main_phases.run_adaptive_tcp", new=AsyncMock(return_value=aq)
        ) as run_tcp,
        patch("blockchecks.main_phases.resolve_probe_backend", return_value="lua_bridge"),
        patch("blockchecks.main_phases.persist_adaptive_weights", new=AsyncMock()),
    ):
        asyncio.run(_run_tcp_adaptive(ctx, progress))
    assert run_tcp.await_args.kwargs.get("quarantine") is not None
    ctx.aq_result = aq
    ctx.db.domain_pass_rows.assert_not_called()


def test_tcp_adaptive_seeds_quarantine_on_resume():
    from blockchecks.main_phases import _run_tcp_adaptive

    ctx = _mk_ctx()
    ctx.tcp_items = [MagicMock()]
    ctx.domains = ["a.com"]
    ctx.db = MagicMock()
    ctx.db.domain_pass_rows = AsyncMock(return_value=[("dead.example", 400, 0)])
    ctx.db.quarantine_domain = AsyncMock()
    ctx.db.get_resume_skip_tcp_keys = AsyncMock(return_value=set())
    ctx.args.resume = True
    ctx.args.adaptive_epsilon = 0.1
    ctx.args.no_adaptive_weights = True
    ctx.args.timeout = 5.0
    ctx.args.protocol = "tls12"
    ctx.args.parallel = 2
    ctx.args.disable_ech = False
    aq = MagicMock()
    aq.done = 0
    aq.passed = 0
    aq.weights = {}
    aq.metrics = MagicMock()
    aq.metrics.time_to_first_pass = None
    aq.metrics.fanout_enqueued = 0
    aq.metrics.half_mark_jobs = False
    progress = SimpleNamespace(done=0, skipped=0, passed=0, report=lambda: None)
    with (
        patch(
            "blockchecks.main_phases.build_adaptive_queue",
            new=AsyncMock(return_value=([MagicMock()], 0)),
        ),
        patch("blockchecks.main_phases.run_adaptive_tcp", new=AsyncMock(return_value=aq)),
        patch("blockchecks.main_phases.resolve_probe_backend", return_value="lua_bridge"),
        patch("blockchecks.main_phases.persist_adaptive_weights", new=AsyncMock()),
    ):
        asyncio.run(_run_tcp_adaptive(ctx, progress))
    ctx.db.domain_pass_rows.assert_awaited()


def test_tcp_adaptive_none_result_raises():
    from blockchecks.main_phases import _run_tcp_adaptive

    ctx = _mk_ctx()
    ctx.tcp_items = [MagicMock()]
    ctx.domains = ["a.com"]
    ctx.db = MagicMock()
    ctx.args.resume = False
    ctx.args.adaptive_epsilon = 0.1
    ctx.args.no_adaptive_weights = True
    ctx.args.timeout = 5.0
    ctx.args.protocol = "tls12"
    ctx.args.parallel = 2
    ctx.args.disable_ech = False
    progress = SimpleNamespace(done=0, skipped=0, passed=0, report=lambda: None)
    with (
        patch(
            "blockchecks.main_phases.build_adaptive_queue",
            new=AsyncMock(return_value=([MagicMock()], 0)),
        ),
        patch("blockchecks.main_phases.run_adaptive_tcp", new=AsyncMock(return_value=None)),
        patch("blockchecks.main_phases.resolve_probe_backend", return_value="lua_bridge"),
    ):
        with pytest.raises(RuntimeError, match="without result"):
            asyncio.run(_run_tcp_adaptive(ctx, progress))


def test_tcp_family_gates():
    from blockchecks.main_phases import _run_tcp_family_gates

    ctx = _mk_ctx()
    ctx.tcp_items = [MagicMock()]
    ctx.domains = ["a.com"]
    ctx.args.resume = False
    ctx.args.timeout = 5.0
    ctx.scan_level = "fast"
    progress = SimpleNamespace(done=0, skipped=0, passed=0, report=lambda: None)
    with patch(
        "blockchecks.main_phases.run_tcp_with_family_gates",
        new=AsyncMock(return_value=([MagicMock()], 1, 0, 1)),
    ):
        asyncio.run(_run_tcp_family_gates(ctx, progress))
    assert progress.done == 1


def test_tcp_fanout():
    from blockchecks.main_phases import _run_tcp_fanout

    ctx = _mk_ctx()
    ctx.tcp_items = [MagicMock()]
    ctx.domains = ["a.com", "b.com"]
    ctx.args.resume = False
    ctx.args.timeout = 5.0
    ctx.args.protocol = "tls12"
    ctx.curl_parallel = 2
    progress = SimpleNamespace(done=0, skipped=0, passed=0, report=lambda: None)
    with (
        patch("blockchecks.main_phases.resolve_probe_backend", return_value="lua_bridge"),
        patch("blockchecks.main_phases.fanout_batches", return_value=[["a.com", "b.com"]]),
        patch.object(
            ctx.runner,
            "test_tcp_domains",
            new=AsyncMock(return_value=[MagicMock(success=True), MagicMock(success=False)]),
        ),
    ):
        asyncio.run(_run_tcp_fanout(ctx, progress))
    assert progress.passed == 1


def test_run_pairs_phase_with_working_tcp():
    from blockchecks.main_phases import run_pairs_phase

    ctx = _mk_ctx(udp_items=[MagicMock()])
    ctx.args.tcp_only = False
    ctx.args.pair_max = 10
    ctx.args.resume = False
    ctx.args.udp_timeout = 3.0
    detail = {"name": "s1", "status": "PASS", "latency_ms": 10}
    ctx.db.get_working_tcp_details = AsyncMock(return_value=[detail])
    ctx.db.get_best_by_coverage = AsyncMock(return_value=[])
    it = MagicMock()
    it.label = "s1"
    it.strategy = "fake:s1"
    ctx.tcp_items = [it]
    pair = MagicMock()
    pair.overall = "PASS"
    ctx.runner.test_pair_matrix = AsyncMock(return_value=[pair])
    with (
        patch(
            "blockchecks.checkers.voice_dns.resolve_voice_targets",
            return_value=[("1.2.3.4", 50004)],
        ),
        patch("blockchecks.checkers.voice_dns.pair_log_domain", return_value="a.com"),
    ):
        asyncio.run(run_pairs_phase(ctx, "1.2.3.4", 50004))


def test_sequential_bridge_isolates_domains():
    """Parallel bridge workers must probe distinct domains (no all-youtube)."""
    from blockchecks.main_phases import _run_tcp_sequential_bridge

    ctx = _mk_ctx()
    ctx.parallel = 4
    ctx.args.resume = False
    ctx.args.timeout = 1.0
    ctx.runner.bridge_batch = 3

    # (start_order, end_order, domains) — batches are recorded with their
    # relative overlap; two batches that overlap in time must not share a domain.
    probe_log: list[tuple[int, int, list[str]]] = []
    order = {"next": 0}

    async def fake_probe(items, domain, timeout, backend, domains=None, stop_event=None):
        doms = list(domains or [domain] * len(items))
        start = order["next"]
        order["next"] += 1
        await asyncio.sleep(0.05)  # simulate parallel execution window
        probe_log.append((start, order["next"], doms))
        return [SimpleNamespace(success=True) for _ in items]

    ctx.runner._run_probe_batch = fake_probe

    from blockchecks.engine.generators.base import StrategyItem

    ctx.tcp_items = [StrategyItem(label=f"s{i}", strategy=f"fake:repeats={i}") for i in range(3)]
    ctx.domains = ["a.com", "b.com", "c.com", "d.com", "e.com"]

    with patch("blockchecks.engine.config.AQ_DOMAIN_ISOLATE", True):
        ctx.stop = asyncio.Event()
        progress = SimpleNamespace(
            done=0,
            skipped=0,
            passed=0,
            report=lambda: None,
        )
        asyncio.run(_run_tcp_sequential_bridge(ctx, progress))

    assert probe_log, "no batches probed"
    # overlap check: for any pair of batches whose windows overlap, their
    # domain sets must be disjoint (that is the isolation guarantee).
    for i in range(len(probe_log)):
        for j in range(i + 1, len(probe_log)):
            si, ei, di = probe_log[i]
            sj, ej, dj = probe_log[j]
            overlap = max(si, sj) < min(ei, ej)
            if overlap:
                shared = set(di) & set(dj)
                assert not shared, f"overlapping batches share domains: {shared}"
    assert progress.done == 15, progress.done
    assert progress.passed == 15


def test_sequential_bridge_warns_when_isolation_off():
    from blockchecks.main_phases import _run_tcp_sequential_bridge

    ctx = _mk_ctx()
    ctx.parallel = 2
    ctx.args.resume = False
    ctx.args.timeout = 1.0
    ctx.runner.bridge_batch = 10

    async def fake_probe(items, domain, timeout, backend, domains=None, stop_event=None):
        return [SimpleNamespace(success=True) for _ in items]

    ctx.runner._run_probe_batch = fake_probe

    from blockchecks.engine.generators.base import StrategyItem

    ctx.tcp_items = [StrategyItem(label="s1", strategy="fake:repeats=6")]
    ctx.domains = ["a.com", "b.com"]

    with (
        patch("blockchecks.engine.config.AQ_DOMAIN_ISOLATE", False) as iso,
        patch("blockchecks.main_phases.log.warning") as mock_warn,
    ):
        ctx.stop = asyncio.Event()
        progress = SimpleNamespace(
            done=0,
            skipped=0,
            passed=0,
            report=lambda: None,
        )
        asyncio.run(_run_tcp_sequential_bridge(ctx, progress))

    assert iso is not None
    warned = any("domain isolation is OFF" in str(a) for a, _ in mock_warn.call_args_list)
    assert warned, "expected isolation warning"
    assert progress.done == 2


def test_sequential_bridge_progress_updates_during_run():
    """progress.done must reflect completed jobs DURING the phase (regression:
    a frozen [0/N] previously persisted until after gather())."""
    from blockchecks.main_phases import _run_tcp_sequential_bridge

    ctx = _mk_ctx()
    ctx.parallel = 1
    ctx.args.resume = False
    ctx.args.timeout = 1.0
    ctx.runner.bridge_batch = 2

    seen_done: list[int] = []

    async def fake_probe(items, domain, timeout, backend, domains=None, stop_event=None):
        await asyncio.sleep(0.02)
        return [SimpleNamespace(success=True) for _ in items]

    ctx.runner._run_probe_batch = fake_probe

    from blockchecks.engine.generators.base import StrategyItem

    ctx.tcp_items = [StrategyItem(label=f"s{i}", strategy="fake:repeats=6") for i in range(4)]
    ctx.domains = ["a.com"]

    with patch("blockchecks.engine.config.AQ_DOMAIN_ISOLATE", False):
        ctx.stop = asyncio.Event()
        progress = SimpleNamespace(
            done=0,
            skipped=0,
            passed=0,
            report=lambda: seen_done.append(progress.done),
        )
        asyncio.run(_run_tcp_sequential_bridge(ctx, progress))

    # report() is called on each flush; with 1 worker + bridge_batch=2 there are
    # at least 2 flushes (2 jobs each), so progress.done must grow past 0 mid-run.
    assert progress.done == 4, progress.done
    assert any(d > 0 for d in seen_done), f"progress never advanced mid-run: {seen_done}"
