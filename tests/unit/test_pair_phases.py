"""Unit tests for pair_phases — the scan/pair orchestration helpers.

Covers the pure / DB-independent functions with mocked external deps
(dns, preflight, store, generators).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.cli.commands.pair_phases import (
    StopHandlerState,
    build_pair_runner,
    finalize_pair_run,
    load_strategy_items,
    prepare_dns_and_preflight,
    print_pair_banner,
    resolve_preset_domains,
    resolve_resume_checkpoint,
    run_adaptive_pair_phase,
    run_standard_pair_phase,
    validate_pair_domain,
)

pytestmark = pytest.mark.unit


def _args(**over):
    base = dict(
        domain="youtube.com",
        preset=None,
        allow_unsafe_domains=False,
        no_secure_dns=False,
        skip_dns_audit=False,
        allow_dns_hijack=False,
        doh_server=None,
        fixed_ip=None,
        force=False,
        resume=False,
        timeout=3.0,
        udp_timeout=3.0,
        protocol="tls12",
        parallel=2,
        scan_level="fast",
        max=10,
        generate=True,
        user_matrix="",
        strategy_preset=None,
        config=None,
        udp_config=None,
        tcp_sources="custom,configs",
        udp_sources="custom",
        tcp_only=False,
        configs_dir=None,
        ip="35.217.5.42",
        port=50006,
        full_voice=False,
        udp_bypass=False,
        auto_discover=None,
        discover_dns=None,
        no_auto_pin=False,
        disable_ech=False,
        no_wssize=False,
        lua_bridge=False,
        bridge_batch=500,
        lua_bridge_compare=False,
        lua_extra=None,
        out_dir=None,
        db=":memory:",
        adaptive=False,
        fan_out=False,
        no_family_gates=False,
        adaptive_epsilon=0.1,
        no_adaptive_weights=False,
    )
    base.update(over)
    return SimpleNamespace(**base)


# ── resolve_preset_domains / validate_pair_domain ────────────────────


def test_resolve_preset_domains_no_preset():
    args = _args(preset=None)
    domains, rc = resolve_preset_domains(args)
    assert rc is None and domains == []


def test_resolve_preset_domains_ok():
    args = _args(preset="general")
    loaded = MagicMock()
    loaded.domains = ["a.com", "b.com"]
    loaded.skipped = []
    with patch("blockchecks.cli.commands.pair_phases.load_preset", return_value=loaded):
        domains, rc = resolve_preset_domains(args)
    assert rc is None
    assert domains == ["a.com", "b.com"]


def test_resolve_preset_domains_path_error():
    args = _args(preset="bad")
    with patch(
        "blockchecks.cli.commands.pair_phases.load_preset",
        side_effect=__import__(
            "blockchecks.cli.presets", fromlist=["PresetPathError"]
        ).PresetPathError("nope"),
    ):
        domains, rc = resolve_preset_domains(args)
    assert rc == 1 and domains == []


def test_resolve_preset_domains_empty_after_denylist():
    args = _args(preset="general")
    loaded = MagicMock()
    loaded.domains = []
    loaded.skipped = []
    with patch("blockchecks.cli.commands.pair_phases.load_preset", return_value=loaded):
        domains, rc = resolve_preset_domains(args)
    assert rc == 1


def test_validate_pair_domain_missing():
    args = _args(domain="", preset=None)
    rc = validate_pair_domain(args, [])
    assert rc == 1


def test_validate_pair_domain_sets_from_preset():
    args = _args(domain="", preset="general")
    rc = validate_pair_domain(args, ["a.com"])
    assert rc is None
    assert args.domain == "a.com"


def test_validate_pair_domain_ok():
    args = _args(domain="youtube.com")
    assert validate_pair_domain(args, []) is None


# ── prepare_dns_and_preflight ─────────────────────────────────────────


def test_prepare_dns_rc_short_circuits():
    args = _args()
    with (
        patch(
            "blockchecks.cli.commands.pair_phases.prepare_dns_for_run",
            return_value=(None, [], 7),
        ),
        patch("blockchecks.data_block.provider.provider_name"),
    ):
        res = asyncio.run(prepare_dns_and_preflight(args, []))
    assert res.exit_code == 7


def test_prepare_dns_preflight_exit_code():
    args = _args()
    preflight = MagicMock()
    preflight.exit_code = 3
    preflight.error = "boom"
    with (
        patch(
            "blockchecks.cli.commands.pair_phases.prepare_dns_for_run",
            return_value=(MagicMock(), [], None),
        ),
        patch(
            "blockchecks.engine.preflight.run_preflight_async",
            new=AsyncMock(return_value=preflight),
        ),
        patch("blockchecks.data_block.provider.provider_name"),
        patch("blockchecks.checkers.ip_pin.load_pins", return_value={}),
    ):
        res = asyncio.run(prepare_dns_and_preflight(args, []))
    assert res.exit_code == 3


def test_prepare_dns_prolog_skip_domain():
    args = _args()
    preflight = MagicMock()
    preflight.exit_code = None
    preflight.skip_domains = ["youtube.com"]
    with (
        patch(
            "blockchecks.cli.commands.pair_phases.prepare_dns_for_run",
            return_value=(MagicMock(), [], None),
        ),
        patch(
            "blockchecks.engine.preflight.run_preflight_async",
            new=AsyncMock(return_value=preflight),
        ),
        patch("blockchecks.data_block.provider.provider_name"),
        patch("blockchecks.checkers.ip_pin.load_pins", return_value={}),
    ):
        res = asyncio.run(prepare_dns_and_preflight(args, []))
    assert res.exit_code == 0


def test_prepare_dns_ok_returns_no_exit():
    args = _args()
    preflight = MagicMock()
    preflight.exit_code = None
    preflight.skip_domains = []
    with (
        patch(
            "blockchecks.cli.commands.pair_phases.prepare_dns_for_run",
            return_value=(MagicMock(), [], None),
        ),
        patch(
            "blockchecks.engine.preflight.run_preflight_async",
            new=AsyncMock(return_value=preflight),
        ),
        patch("blockchecks.data_block.provider.provider_name"),
        patch("blockchecks.checkers.ip_pin.load_pins", return_value={}),
    ):
        res = asyncio.run(prepare_dns_and_preflight(args, []))
    assert res.exit_code is None


# ── build_pair_runner ─────────────────────────────────────────────────


def test_build_pair_runner_passes_settings():
    args = _args()
    with (
        patch(
            "blockchecks.cli.commands.pair_phases.repeats_from_args",
            return_value=(1, False, "fast", False),
        ),
        patch(
            "blockchecks.cli.commands.pair_phases.resolve_probe_backend",
            return_value="classic",
        ),
        patch("blockchecks.cli.commands.pair_phases.AsyncTestRunner") as RunnerCls,
    ):
        build_pair_runner(args, MagicMock(), MagicMock(), [], 2)
    kwargs = RunnerCls.call_args.kwargs
    assert kwargs["pool_size"] == 2
    assert kwargs["repeats"] == 1
    assert kwargs["bridge_batch"] == 500


# ── StopHandlerState ──────────────────────────────────────────────────


def test_stop_handler_state_sets_event():
    from blockchecks.engine.run_deadline import RunDeadline

    ev = asyncio.Event()
    deadline = RunDeadline(ev, budget_sec=60.0)
    state = StopHandlerState()
    state.request_stop(deadline, ev)
    assert state.signal_interrupted
    assert deadline.reason == "signal"


# ── print_pair_banner ─────────────────────────────────────────────────


def test_banner_returns_1_no_tcp():
    args = _args(tcp_only=False)
    rc = print_pair_banner(args, [], [], [], "1.2.3.4", 50004, False, 2)
    assert rc == 1


def test_banner_ok():
    args = _args()
    rc = print_pair_banner(
        args,
        [],
        [MagicMock()],
        [MagicMock()],
        "1.2.3.4",
        50004,
        False,
        2,
    )
    assert rc is None


# ── resolve_resume_checkpoint ─────────────────────────────────────────


def test_resume_no_checkpoint():
    args = _args(resume=True)
    db = MagicMock()
    db.latest_checkpoint = AsyncMock(return_value=None)
    resume_from, rc = asyncio.run(resolve_resume_checkpoint(args, db, "fp"))
    assert rc is None and resume_from is None


def test_resume_fingerprint_mismatch():
    args = _args(resume=True)
    db = MagicMock()
    cp = MagicMock()
    cp.fingerprint = "old"
    db.latest_checkpoint = AsyncMock(return_value=cp)
    with patch("blockchecks.cli.commands.pair_phases.fingerprint_mismatch", return_value=True):
        _, rc = asyncio.run(resolve_resume_checkpoint(args, db, "new"))
    assert rc == 1


def test_resume_match():
    args = _args(resume=True)
    db = MagicMock()
    cp = MagicMock()
    cp.fingerprint = "fp"
    db.latest_checkpoint = AsyncMock(return_value=cp)
    with patch("blockchecks.cli.commands.pair_phases.fingerprint_mismatch", return_value=False):
        resume_from, rc = asyncio.run(resolve_resume_checkpoint(args, db, "fp"))
    assert rc is None and resume_from is cp


# ── load_strategy_items ───────────────────────────────────────────────


def test_load_strategy_items_config_path():
    args = _args(config="/tmp/my.conf", generate=False, user_matrix="")
    res = asyncio.run(load_strategy_items(args, MagicMock()))
    assert res.error_code is None
    assert len(res.tcp_items) == 1
    assert res.tcp_items[0].is_config


def test_load_strategy_items_generated():
    args = _args(generate=True, config=None, user_matrix="")
    gen = MagicMock()
    gen.generate_tcp = AsyncMock(return_value=[MagicMock()])
    gen.generate_udp = AsyncMock(return_value=[MagicMock()])
    with patch("blockchecks.cli.commands.pair_phases.MatrixGenerator", return_value=gen):
        res = asyncio.run(load_strategy_items(args, MagicMock()))
    assert res.error_code is None
    assert len(res.tcp_items) == 1
    assert res.tcp_sources_list == ["custom", "configs"]


def test_load_strategy_items_tcp_only_skips_udp():
    args = _args(generate=True, config=None, user_matrix="", tcp_only=True)
    gen = MagicMock()
    gen.generate_tcp = AsyncMock(return_value=[MagicMock()])
    gen.generate_udp = AsyncMock(return_value=[])
    with patch("blockchecks.cli.commands.pair_phases.MatrixGenerator", return_value=gen):
        res = asyncio.run(load_strategy_items(args, MagicMock()))
    assert len(res.udp_items) == 0


def test_load_strategy_items_strategy_preset_not_found():
    args = _args(generate=True, strategy_preset="nope")
    with patch(
        "blockchecks.cli.presets.resolve_strategy_preset",
        side_effect=FileNotFoundError,
    ):
        res = asyncio.run(load_strategy_items(args, MagicMock()))
    assert res.error_code == 1


# ── finalize_pair_run ─────────────────────────────────────────────────


def test_finalize_no_tcp_passed_returns_1():
    args = _args(tcp_only=True)
    db = MagicMock()
    with (
        patch(
            "blockchecks.engine.run_finalize.maybe_write_best_config_data_block", new=AsyncMock()
        ),
        patch("blockchecks.engine.run_finalize.maybe_sync_data_block", new=AsyncMock()),
        patch("blockchecks.cli.commands.pair_phases.write_run_summary", return_value=None),
        patch("blockchecks.cli.commands.pair_phases.run_exit_code", return_value=0),
    ):
        rc = asyncio.run(
            finalize_pair_run(args, db, None, asyncio.Event(), StopHandlerState(), 0, [], None)
        )
    assert rc == 1


def test_finalize_tcp_passed_returns_exit_code():
    args = _args(tcp_only=True)
    db = MagicMock()
    with (
        patch(
            "blockchecks.engine.run_finalize.maybe_write_best_config_data_block", new=AsyncMock()
        ),
        patch("blockchecks.engine.run_finalize.maybe_sync_data_block", new=AsyncMock()),
        patch("blockchecks.cli.commands.pair_phases.write_run_summary", return_value=None),
        patch("blockchecks.cli.commands.pair_phases.run_exit_code", return_value=0),
    ):
        rc = asyncio.run(
            finalize_pair_run(args, db, None, asyncio.Event(), StopHandlerState(), 2, [], None)
        )
    assert rc == 0


def test_finalize_pairs_fail_returns_1():
    args = _args(tcp_only=False)
    db = MagicMock()
    bad_pair = MagicMock()
    bad_pair.overall = "FAIL"
    with (
        patch(
            "blockchecks.engine.run_finalize.maybe_write_best_config_data_block", new=AsyncMock()
        ),
        patch("blockchecks.engine.run_finalize.maybe_sync_data_block", new=AsyncMock()),
        patch("blockchecks.cli.commands.pair_phases.write_run_summary", return_value=None),
        patch("blockchecks.cli.commands.pair_phases.run_exit_code", return_value=0),
    ):
        rc = asyncio.run(
            finalize_pair_run(
                args, db, None, asyncio.Event(), StopHandlerState(), 2, [bad_pair], None
            )
        )
    assert rc == 1


# ── run_standard_pair_phase / run_adaptive_pair_phase ────────────────


def _item(label="s1"):
    it = MagicMock()
    it.label = label
    it.strategy = f"fake:{label}"
    it.is_config = False
    return it


def _result(label="s1", success=True):
    r = MagicMock()
    r.item = _item(label)
    r.success = success
    r.domain = "youtube.com"
    return r


def test_run_standard_pair_phase_tcp_only():
    args = _args(tcp_only=True)
    runner = AsyncMock()
    runner.test_batch_tcp = AsyncMock(return_value=[_result("s1"), _result("s2", False)])
    phase = asyncio.run(
        run_standard_pair_phase(
            args,
            runner,
            [_item("s1"), _item("s2")],
            [],
            ["youtube.com"],
            "1.2.3.4",
            50004,
            False,
            None,
            "fp",
            asyncio.Event(),
            "fast",
            False,
            set(),
        )
    )
    assert phase.tcp_passed == 1
    assert phase.pairs == []


def test_run_standard_pair_phase_family_gates():
    args = _args(tcp_only=True)
    runner = AsyncMock()
    with patch(
        "blockchecks.cli.commands.pair_phases.run_tcp_with_family_gates",
        new=AsyncMock(return_value=([_result("s1"), _result("s2")], [], 0, 0)),
    ):
        phase = asyncio.run(
            run_standard_pair_phase(
                args,
                runner,
                [_item("s1"), _item("s2")],
                [],
                ["youtube.com"],
                "1.2.3.4",
                50004,
                False,
                None,
                "fp",
                asyncio.Event(),
                "fast",
                True,
                set(),
            )
        )
    assert phase.tcp_passed == 2


def test_run_standard_pair_phase_stop_event_breaks():
    args = _args(tcp_only=True)
    runner = AsyncMock()
    ev = asyncio.Event()
    ev.set()
    phase = asyncio.run(
        run_standard_pair_phase(
            args,
            runner,
            [_item("s1")],
            [],
            ["youtube.com"],
            "1.2.3.4",
            50004,
            False,
            None,
            "fp",
            ev,
            "fast",
            False,
            set(),
        )
    )
    assert phase.tcp_passed == 0
    runner.test_batch_tcp.assert_not_called()


def test_run_adaptive_pair_phase():
    args = _args()
    runner = AsyncMock()
    aq_result = MagicMock()
    aq_result.passed = 3
    aq_result.weights = {}
    aq_result.done = 5
    m = MagicMock()
    m.time_to_first_pass = 1.0
    m.fanout_enqueued = 2
    aq_result.metrics = m
    with (
        patch(
            "blockchecks.cli.commands.pair_phases.build_adaptive_queue",
            new=AsyncMock(return_value=([MagicMock()], 0)),
        ),
        patch(
            "blockchecks.cli.commands.pair_phases.run_adaptive_tcp",
            new=AsyncMock(return_value=aq_result),
        ),
        patch(
            "blockchecks.cli.commands.pair_phases.resolve_probe_backend",
            return_value="classic",
        ),
        patch(
            "blockchecks.cli.commands.pair_phases.persist_adaptive_weights",
            new=AsyncMock(),
        ),
    ):
        phase = asyncio.run(
            run_adaptive_pair_phase(
                args,
                runner,
                MagicMock(),
                [_item("s1")],
                [],
                ["youtube.com"],
                "1.2.3.4",
                50004,
                False,
                None,
                "fp",
                asyncio.Event(),
                2,
                "tls12",
                [],
            )
        )
    assert phase.tcp_passed == 3


# ── discover_voice_endpoints / register_stop_handlers / configs_dir ──


def test_discover_voice_endpoints_mutex_error():
    from blockchecks.cli.commands.pair_phases import discover_voice_endpoints

    args = _args(discover_dns=5, auto_discover=5)
    ctx, rc = asyncio.run(discover_voice_endpoints(args))
    assert rc == 1


def test_discover_voice_endpoints_dns_alive():
    from blockchecks.cli.commands.pair_phases import discover_voice_endpoints

    args = _args(discover_dns=3)
    with (
        patch(
            "blockchecks.checkers.voice_dns.discover_dns_alive",
            new=AsyncMock(
                return_value=[
                    {
                        "ip": "1.2.3.4",
                        "port": 50004,
                        "hostname": "h",
                        "source": "dns",
                        "stun_ms": 5,
                        "method": "x",
                        "bootstrap": True,
                    }
                ]
            ),
        ),
        patch("blockchecks.checkers.voice_dns.check_discover_mutex", return_value=None),
        patch("blockchecks.checkers.voice_discovery.load_token", return_value=None),
    ):
        ctx, rc = asyncio.run(discover_voice_endpoints(args))
    assert rc is None
    assert ctx.voice_ip == "1.2.3.4"


def test_discover_voice_endpoints_auto_discover():
    from blockchecks.cli.commands.pair_phases import discover_voice_endpoints

    args = _args(auto_discover=3)
    with (
        patch(
            "blockchecks.checkers.voice_discovery.discover_multiple",
            new=AsyncMock(return_value=[{"ip": "9.9.9.9", "port": 50001, "hostname": "h"}]),
        ),
        patch("blockchecks.checkers.voice_dns.check_discover_mutex", return_value=None),
        patch("blockchecks.checkers.voice_discovery.load_token", return_value=None),
    ):
        ctx, rc = asyncio.run(discover_voice_endpoints(args))
    assert rc is None
    assert ctx.voice_ip == "9.9.9.9"


def test_discover_voice_endpoints_full_voice_no_token():
    from blockchecks.cli.commands.pair_phases import discover_voice_endpoints

    args = _args(full_voice=True)
    with (
        patch("blockchecks.checkers.voice_dns.check_discover_mutex", return_value=None),
        patch("blockchecks.checkers.voice_discovery.load_token", return_value=None),
    ):
        ctx, rc = asyncio.run(discover_voice_endpoints(args))
    assert rc is None
    assert ctx.full_voice is False
    assert ctx.has_token is False


def test_register_stop_handlers(monkeypatch):
    from blockchecks.cli.commands.pair_phases import (
        StopHandlerState,
        register_stop_handlers,
    )

    ev = asyncio.Event()
    loop = MagicMock()
    state = StopHandlerState()
    with patch("blockchecks.cli.commands.pair_phases.asyncio.get_running_loop", return_value=loop):
        register_stop_handlers(loop, state, None, ev)
    assert loop.add_signal_handler.call_count == 3


def test_load_strategy_items_configs_dir(tmp_path):
    conf_dir = tmp_path / "cfgs"
    conf_dir.mkdir()
    (conf_dir / "tcp_a.conf").write_text("--qnum=200\n")
    (conf_dir / "udp_voice_b.conf").write_text("--qnum=201\n")
    args = _args(generate=False, config=None, configs_dir=str(conf_dir), user_matrix="")
    with patch("blockchecks.cli.commands.pair_phases.StrategyLoader") as LoaderCls:
        LoaderCls.return_value.from_config_dir.return_value = [
            str(conf_dir / "tcp_a.conf"),
            str(conf_dir / "udp_voice_b.conf"),
        ]
        res = asyncio.run(load_strategy_items(args, MagicMock()))
    assert len(res.tcp_items) == 1
    assert len(res.udp_items) == 1
