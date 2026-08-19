"""Unit tests for the async pair/scan CLI command (cmd_pair).

Mocks run_session + pair_phases helpers so no netns/DB writes occur.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.cli.commands.pair import cmd_pair

pytestmark = pytest.mark.unit


def _pair_args(**over):
    base = dict(
        list_presets=False,
        db=":memory:",
        db_batch=10,
        domain="youtube.com",
        preset=None,
        tcp_only=False,
        parallel=2,
        timeout=3.0,
        udp_timeout=3.0,
        scan_level="fast",
        max=10,
        protocol="tls12",
        adaptive=False,
        fan_out=False,
        curl_parallel=2,
        no_family_gates=False,
        max_timeh=None,
        max_timem=None,
        generate="custom,configs",
        tcp_sources="custom,configs",
        udp_sources="custom",
    )
    base.update(over)
    return SimpleNamespace(**base)


def test_pair_cli_udp_sources_default():
    from blockchecks.cli.parser import build_parser

    ns = build_parser().parse_args(["pair", "-d", "discord.com"])
    assert ns.udp_sources == "custom,standard_udp"


def _run(coro):
    return asyncio.run(coro)


def test_pair_list_presets_returns_0():
    args = _pair_args(list_presets=True)
    with patch("blockchecks.cli.commands.pair.list_presets") as lp:
        rc = _run(cmd_pair(args))
    assert rc == 0
    lp.assert_called_once()


def test_pair_dns_exit_code_short_circuits():
    args = _pair_args()
    with patch(
        "blockchecks.service.run_control.register_active_run"
    ), patch(
        "blockchecks.service.run_control.clear_active_run"
    ), patch(
        "blockchecks.cli.commands.pair.open_run_store"
    ) as open_store, patch(
        "blockchecks.cli.commands.pair.resolve_preset_domains"
    ) as resolve_preset, patch(
        "blockchecks.cli.commands.pair.validate_pair_domain"
    ) as validate, patch(
        "blockchecks.cli.commands.pair.prepare_dns_and_preflight"
    ) as prep:
        open_store.return_value.init = AsyncMock()
        resolve_preset.return_value = ([], None)
        validate.return_value = None
        prep.return_value = SimpleNamespace(exit_code=7, dns_cache=None, dns_audits=[])
        rc = _run(cmd_pair(args))
    assert rc == 7


def test_pair_standard_phase_success():
    args = _pair_args()
    phase = MagicMock()
    phase.tcp_passed = 2
    phase.pairs = [("t", "u")]
    phase.aq_result = None
    with patch(
        "blockchecks.service.run_control.register_active_run"
    ), patch(
        "blockchecks.service.run_control.clear_active_run"
    ), patch("blockchecks.cli.commands.pair.open_run_store") as open_store, patch(
        "blockchecks.cli.commands.pair.finalize_db_and_weights", AsyncMock()
    ), patch(
        "blockchecks.cli.commands.pair.resolve_preset_domains"
    ) as resolve_preset, patch(
        "blockchecks.cli.commands.pair.validate_pair_domain"
    ) as validate, patch(
        "blockchecks.cli.commands.pair.prepare_dns_and_preflight"
    ) as prep, patch(
        "blockchecks.cli.commands.pair.build_pair_runner"
    ) as build, patch(
        "blockchecks.cli.commands.pair.discover_voice_endpoints"
    ) as voice, patch(
        "blockchecks.cli.commands.pair.load_strategy_items"
    ) as load, patch(
        "blockchecks.cli.commands.pair.print_pair_banner"
    ) as banner, patch(
        "blockchecks.cli.commands.pair.resolve_resume_checkpoint"
    ) as resume, patch(
        "blockchecks.cli.commands.pair.run_standard_pair_phase", AsyncMock()
    ) as std, patch(
        "blockchecks.cli.commands.pair.register_stop_handlers"
    ), patch(
        "blockchecks.cli.commands.pair.finalize_pair_run", AsyncMock()
    ) as fin:
        open_store.return_value.init = AsyncMock()
        resolve_preset.return_value = ([], None)
        validate.return_value = None
        prep.return_value = SimpleNamespace(exit_code=None, dns_cache=None, dns_audits=[])
        build.return_value = AsyncMock()
        voice.return_value = (SimpleNamespace(voice_ip="1.2.3.4", voice_port=50004,
                                              full_voice=False, multi_eps=[]), None)
        load.return_value = SimpleNamespace(error_code=None, tcp_items=[], udp_items=[],
                                            tcp_sources_list=["custom"], run_set=set())
        banner.return_value = None
        resume.return_value = (None, None)
        std.return_value = phase
        fin.return_value = 0
        rc = _run(cmd_pair(args))
    assert rc == 0
    std.assert_called_once()
    fin.assert_called_once()


def test_pair_adaptive_phase_chosen():
    args = _pair_args(adaptive=True)
    phase = MagicMock()
    phase.tcp_passed = 1
    phase.pairs = []
    phase.aq_result = None
    with patch(
        "blockchecks.service.run_control.register_active_run"
    ), patch(
        "blockchecks.service.run_control.clear_active_run"
    ), patch("blockchecks.cli.commands.pair.open_run_store") as open_store, patch(
        "blockchecks.cli.commands.pair.finalize_db_and_weights", AsyncMock()
    ), patch(
        "blockchecks.cli.commands.pair.resolve_preset_domains"
    ) as resolve_preset, patch(
        "blockchecks.cli.commands.pair.validate_pair_domain"
    ) as validate, patch(
        "blockchecks.cli.commands.pair.prepare_dns_and_preflight"
    ) as prep, patch(
        "blockchecks.cli.commands.pair.build_pair_runner"
    ) as build, patch(
        "blockchecks.cli.commands.pair.discover_voice_endpoints"
    ) as voice, patch(
        "blockchecks.cli.commands.pair.load_strategy_items"
    ) as load, patch(
        "blockchecks.cli.commands.pair.print_pair_banner"
    ) as banner, patch(
        "blockchecks.cli.commands.pair.resolve_resume_checkpoint"
    ) as resume, patch(
        "blockchecks.cli.commands.pair.run_adaptive_pair_phase", AsyncMock()
    ) as adaptive, patch(
        "blockchecks.cli.commands.pair.register_stop_handlers"
    ), patch(
        "blockchecks.cli.commands.pair.finalize_pair_run", AsyncMock()
    ) as fin:
        open_store.return_value.init = AsyncMock()
        resolve_preset.return_value = ([], None)
        validate.return_value = None
        prep.return_value = SimpleNamespace(exit_code=None, dns_cache=None, dns_audits=[])
        build.return_value = AsyncMock()
        voice.return_value = (SimpleNamespace(voice_ip="1.2.3.4", voice_port=50004,
                                              full_voice=False, multi_eps=[]), None)
        load.return_value = SimpleNamespace(error_code=None, tcp_items=[], udp_items=[],
                                            tcp_sources_list=["custom"], run_set=set())
        banner.return_value = None
        resume.return_value = (None, None)
        adaptive.return_value = phase
        fin.return_value = 0
        rc = _run(cmd_pair(args))
    assert rc == 0
    adaptive.assert_called_once()


def test_pair_banner_rc_short_circuits():
    args = _pair_args()
    with patch(
        "blockchecks.service.run_control.register_active_run"
    ), patch(
        "blockchecks.service.run_control.clear_active_run"
    ), patch("blockchecks.cli.commands.pair.open_run_store") as open_store, patch(
        "blockchecks.cli.commands.pair.finalize_db_and_weights", AsyncMock()
    ), patch(
        "blockchecks.cli.commands.pair.resolve_preset_domains"
    ) as resolve_preset, patch(
        "blockchecks.cli.commands.pair.validate_pair_domain"
    ) as validate, patch(
        "blockchecks.cli.commands.pair.prepare_dns_and_preflight"
    ) as prep, patch(
        "blockchecks.cli.commands.pair.build_pair_runner"
    ) as build, patch(
        "blockchecks.cli.commands.pair.discover_voice_endpoints"
    ) as voice, patch(
        "blockchecks.cli.commands.pair.load_strategy_items"
    ) as load, patch(
        "blockchecks.cli.commands.pair.print_pair_banner"
    ) as banner, patch(
        "blockchecks.cli.commands.pair.register_stop_handlers"
    ):
        open_store.return_value.init = AsyncMock()
        resolve_preset.return_value = ([], None)
        validate.return_value = None
        prep.return_value = SimpleNamespace(exit_code=None, dns_cache=None, dns_audits=[])
        build.return_value = AsyncMock()
        voice.return_value = (SimpleNamespace(voice_ip="1.2.3.4", voice_port=50004,
                                              full_voice=False, multi_eps=[]), None)
        load.return_value = SimpleNamespace(error_code=None, tcp_items=[], udp_items=[],
                                            tcp_sources_list=["custom"], run_set=set())
        banner.return_value = 5
        rc = _run(cmd_pair(args))
    assert rc == 5


def test_pair_tcp_only_uses_scan_session():
    """tcp_only=True → run_session command='scan', still full flow."""
    args = _pair_args(tcp_only=True)
    phase = MagicMock()
    phase.tcp_passed = 1
    phase.pairs = []
    phase.aq_result = None
    with patch(
        "blockchecks.service.run_control.register_active_run"
    ) as reg, patch(
        "blockchecks.service.run_control.clear_active_run"
    ), patch("blockchecks.cli.commands.pair.open_run_store") as open_store, patch(
        "blockchecks.cli.commands.pair.finalize_db_and_weights", AsyncMock()
    ), patch(
        "blockchecks.cli.commands.pair.resolve_preset_domains"
    ) as resolve_preset, patch(
        "blockchecks.cli.commands.pair.validate_pair_domain"
    ) as validate, patch(
        "blockchecks.cli.commands.pair.prepare_dns_and_preflight"
    ) as prep, patch(
        "blockchecks.cli.commands.pair.build_pair_runner"
    ) as build, patch(
        "blockchecks.cli.commands.pair.discover_voice_endpoints"
    ) as voice, patch(
        "blockchecks.cli.commands.pair.load_strategy_items"
    ) as load, patch(
        "blockchecks.cli.commands.pair.print_pair_banner"
    ) as banner, patch(
        "blockchecks.cli.commands.pair.resolve_resume_checkpoint"
    ) as resume, patch(
        "blockchecks.cli.commands.pair.register_stop_handlers"
    ), patch(
        "blockchecks.cli.commands.pair.run_standard_pair_phase", AsyncMock()
    ) as std, patch(
        "blockchecks.cli.commands.pair.finalize_pair_run", AsyncMock()
    ) as fin:
        open_store.return_value.init = AsyncMock()
        resolve_preset.return_value = ([], None)
        validate.return_value = None
        prep.return_value = SimpleNamespace(exit_code=None, dns_cache=None, dns_audits=[])
        build.return_value = AsyncMock()
        voice.return_value = (SimpleNamespace(voice_ip="1.2.3.4", voice_port=50004,
                                              full_voice=False, multi_eps=[]), None)
        load.return_value = SimpleNamespace(error_code=None, tcp_items=[], udp_items=[],
                                            tcp_sources_list=["custom"], run_set=set())
        banner.return_value = None
        resume.return_value = (None, None)
        std.return_value = phase
        fin.return_value = 0
        rc = _run(cmd_pair(args))
    assert rc == 0
    # run_session registers "scan" for tcp_only
    assert any(c.args[0] == "scan" for c in reg.call_args_list)
