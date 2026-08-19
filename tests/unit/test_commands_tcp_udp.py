"""Unit tests for the sync CLI commands cmd_tcp / cmd_udp.

Covers source-loaders, error handling, exit codes and DNS/prep plumbing
without touching netns (mock TestRunner + StrategyLoader + dns).
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from blockchecks.cli.commands.tcp import cmd_tcp
from blockchecks.cli.commands.udp import cmd_udp

pytestmark = pytest.mark.unit


# ── helpers ───────────────────────────────────────────────────────────


def _tcp_args(**over):
    base = dict(
        domain="youtube.com",
        strategy="fake:blob=stun:repeats=6:tcp_ts=-1000",
        config="",
        configs_dir="",
        file="",
        test="",
        test_dir="",
        timeout=3.0,
        no_hostlist=False,
        qnum=200,
        ns="",
        no_secure_dns=False,
        skip_dns_audit=False,
        allow_dns_hijack=False,
        doh_server=None,
        max_timeh=None,
        max_timem=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _udp_args(**over):
    base = dict(
        config="",
        configs_dir="",
        ip="162.159.137.1",
        port=50004,
        discover_dns=None,
        auto_discover=None,
        discover_dns_no_bootstrap=False,
        voice_region=None,
        voice_burst=False,
        timeout=3.0,
        qnum=201,
        ns="",
    )
    base.update(over)
    return SimpleNamespace(**base)


def _report(passed: int, n: int = 2):
    rep = MagicMock()
    rep.passed = passed
    rep.total_time_sec = 1.0
    rep.stopped_reason = ""
    rep.results = [MagicMock() for _ in range(n)]
    return rep


# ── cmd_tcp: source loading ──────────────────────────────────────────


def test_tcp_no_source_returns_error():
    args = _tcp_args(strategy="", config="", configs_dir="", file="", test="")
    with patch("blockchecks.cli.commands.tcp.StrategyLoader"):
        rc = cmd_tcp(args)
    assert rc == 1


def test_tcp_no_strategies_loaded():
    args = _tcp_args()
    with (
        patch("blockchecks.cli.commands.tcp.StrategyLoader") as LoaderCls,
        patch("blockchecks.cli.commands.tcp.prepare_dns_for_run") as dns,
    ):
        LoaderCls.return_value.from_string.return_value = []
        dns.return_value = (None, None, 0)
        rc = cmd_tcp(args)
    assert rc == 1


def test_tcp_strategy_source_runs_sequential():
    args = _tcp_args(strategy="fake:blob=stun:repeats=6:tcp_ts=-1000")
    with (
        patch("blockchecks.cli.commands.tcp.StrategyLoader") as LoaderCls,
        patch("blockchecks.cli.commands.tcp.prepare_dns_for_run") as dns,
        patch("blockchecks.cli.commands.tcp.TestRunner") as RunnerCls,
        patch("blockchecks.data_block.provider.provider_name"),
        patch("blockchecks.cli.commands.tcp.repeats_from_args") as repeats,
    ):
        LoaderCls.return_value.from_string.return_value = ["fake:strategy"]
        dns.return_value = (MagicMock(), None, 0)
        repeats.return_value = (1, False, "fast", False)
        RunnerCls.return_value.test_sequential.return_value = _report(passed=1)
        rc = cmd_tcp(args)
    assert rc == 0
    RunnerCls.return_value.test_sequential.assert_called_once()
    RunnerCls.return_value.test_sequential_configs.assert_not_called()


def test_tcp_config_source_uses_configs_path():
    args = _tcp_args(config="/tmp/x.conf", strategy="")
    with (
        patch("blockchecks.cli.commands.tcp.StrategyLoader") as LoaderCls,
        patch("blockchecks.cli.commands.tcp.prepare_dns_for_run") as dns,
        patch("blockchecks.cli.commands.tcp.TestRunner") as RunnerCls,
        patch("blockchecks.data_block.provider.provider_name"),
        patch("blockchecks.cli.commands.tcp.repeats_from_args") as repeats,
    ):
        LoaderCls.return_value.from_config.return_value = ["/tmp/x.conf"]
        dns.return_value = (MagicMock(), None, 0)
        repeats.return_value = (1, False, "fast", False)
        RunnerCls.return_value.test_sequential_configs.return_value = _report(passed=1)
        rc = cmd_tcp(args)
    assert rc == 0
    RunnerCls.return_value.test_sequential_configs.assert_called_once()


def test_tcp_fail_returns_1():
    args = _tcp_args()
    with (
        patch("blockchecks.cli.commands.tcp.StrategyLoader") as LoaderCls,
        patch("blockchecks.cli.commands.tcp.prepare_dns_for_run") as dns,
        patch("blockchecks.cli.commands.tcp.TestRunner") as RunnerCls,
        patch("blockchecks.data_block.provider.provider_name"),
        patch("blockchecks.cli.commands.tcp.repeats_from_args") as repeats,
    ):
        LoaderCls.return_value.from_string.return_value = ["fake:strategy"]
        dns.return_value = (MagicMock(), None, 0)
        repeats.return_value = (1, False, "fast", False)
        RunnerCls.return_value.test_sequential.return_value = _report(passed=0)
        rc = cmd_tcp(args)
    assert rc == 1


def test_tcp_dns_error_short_circuits():
    args = _tcp_args()
    with (
        patch("blockchecks.cli.commands.tcp.StrategyLoader") as LoaderCls,
        patch("blockchecks.cli.commands.tcp.prepare_dns_for_run") as dns,
        patch("blockchecks.cli.commands.tcp.TestRunner") as RunnerCls,
    ):
        LoaderCls.return_value.from_string.return_value = ["fake:strategy"]
        dns.return_value = (None, None, 3)
        rc = cmd_tcp(args)
    assert rc == 3
    RunnerCls.assert_not_called()


def test_tcp_time_limit_prints_stopped():
    args = _tcp_args(max_timem=60)
    rep = _report(passed=1, n=3)
    rep.stopped_reason = "time_limit"
    with (
        patch("blockchecks.cli.commands.tcp.StrategyLoader") as LoaderCls,
        patch("blockchecks.cli.commands.tcp.prepare_dns_for_run") as dns,
        patch("blockchecks.cli.commands.tcp.TestRunner") as RunnerCls,
        patch("blockchecks.data_block.provider.provider_name"),
        patch("blockchecks.cli.commands.tcp.repeats_from_args") as repeats,
    ):
        LoaderCls.return_value.from_string.return_value = ["fake:a", "fake:b", "fake:c"]
        dns.return_value = (MagicMock(), None, 0)
        repeats.return_value = (1, False, "fast", False)
        RunnerCls.return_value.test_sequential.return_value = rep
        rc = cmd_tcp(args)
    assert rc == 0


def test_tcp_bad_time_limit_returns_1():
    args = _tcp_args(max_timeh=1, max_timem=5)  # mutually exclusive → ValueError
    with patch("blockchecks.cli.commands.tcp.StrategyLoader") as LoaderCls:
        rc = cmd_tcp(args)
    assert rc == 1
    LoaderCls.assert_not_called()


# ── cmd_udp ───────────────────────────────────────────────────────────


def test_udp_mutex_error_returns_1():
    args = _udp_args(discover_dns=5, auto_discover=5)
    with patch("blockchecks.cli.commands.udp.check_discover_mutex") as mutex:
        mutex.return_value = "mutex error"
        rc = cmd_udp(args)
    assert rc == 1


def test_udp_no_source_returns_1():
    args = _udp_args(config="", configs_dir="")
    with patch("blockchecks.cli.commands.udp.check_discover_mutex") as mutex:
        mutex.return_value = None
        rc = cmd_udp(args)
    assert rc == 1


def test_udp_empty_configs_returns_1():
    args = _udp_args(configs_dir="/tmp/cfg")
    with (
        patch("blockchecks.cli.commands.udp.check_discover_mutex") as mutex,
        patch("blockchecks.cli.commands.udp.StrategyLoader") as LoaderCls,
    ):
        mutex.return_value = None
        LoaderCls.return_value.from_config_dir.return_value = []
        rc = cmd_udp(args)
    assert rc == 1


def test_udp_static_ip_runs_udp_probe():
    args = _udp_args(configs_dir="/tmp/cfg")
    with (
        patch("blockchecks.cli.commands.udp.check_discover_mutex") as mutex,
        patch("blockchecks.cli.commands.udp.StrategyLoader") as LoaderCls,
        patch("blockchecks.cli.commands.udp.TestRunner") as RunnerCls,
        patch("blockchecks.cli.commands.udp.resolve_voice_targets") as resolve,
    ):
        mutex.return_value = None
        LoaderCls.return_value.from_config_dir.return_value = ["/tmp/cfg/udp_a.conf"]
        resolve.return_value = [("162.159.137.1", 50004)]
        RunnerCls.return_value.test_sequential_udp.return_value = _report(passed=1)
        rc = cmd_udp(args)
    assert rc == 0
    RunnerCls.return_value.test_sequential_udp.assert_called_once()


def test_udp_discover_dns_fallback_on_error():
    args = _udp_args(configs_dir="/tmp/cfg", ip="162.159.137.1", discover_dns=2)
    with (
        patch("blockchecks.cli.commands.udp.check_discover_mutex") as mutex,
        patch("blockchecks.cli.commands.udp.StrategyLoader") as LoaderCls,
        patch("blockchecks.cli.commands.udp.TestRunner") as RunnerCls,
        patch("blockchecks.cli.commands.udp.resolve_voice_targets") as resolve,
        patch("blockchecks.cli.commands.udp.discover_dns_alive") as discover,
    ):
        mutex.return_value = None
        LoaderCls.return_value.from_config_dir.return_value = ["/tmp/cfg/udp_a.conf"]
        discover.side_effect = RuntimeError("no network")
        resolve.return_value = [("162.159.137.1", 50004)]
        RunnerCls.return_value.test_sequential_udp.return_value = _report(passed=1)
        rc = cmd_udp(args)
    assert rc == 0
    # Fallback to static DEFAULT_VOICE_IP / port
    resolve.assert_called_once()
    call_port = resolve.call_args.args[1]
    assert call_port == 50004


def test_udp_auto_discover_uses_discover_multiple():
    args = _udp_args(configs_dir="/tmp/cfg", ip="35.217.5.42", auto_discover=3)
    with (
        patch("blockchecks.cli.commands.udp.check_discover_mutex") as mutex,
        patch("blockchecks.cli.commands.udp.StrategyLoader") as LoaderCls,
        patch("blockchecks.cli.commands.udp.TestRunner") as RunnerCls,
        patch("blockchecks.cli.commands.udp.resolve_voice_targets") as resolve,
        patch("blockchecks.checkers.voice_discovery.discover_multiple") as discover_multiple,
    ):
        mutex.return_value = None
        LoaderCls.return_value.from_config_dir.return_value = ["/tmp/cfg/udp_a.conf"]
        discover_multiple.return_value = [{"ip": "1.2.3.4", "port": 50001, "method": "x"}]
        resolve.return_value = [("1.2.3.4", 50001)]
        RunnerCls.return_value.test_sequential_udp.return_value = _report(passed=1)
        rc = cmd_udp(args)
    assert rc == 0
    discover_multiple.assert_called_once()
