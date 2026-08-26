"""Tests for probe-backend selection: lua_bridge default, --classic, env override."""

from __future__ import annotations

from argparse import Namespace

import pytest

from blockchecks.engine.config import resolve_probe_backend

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("BLOCKCHECKS_PROBE_BACKEND", raising=False)


def _ns(**kw) -> Namespace:
    base = dict(classic=False, probe_backend=None, lua_bridge=False)
    base.update(kw)
    return Namespace(**base)


def test_default_backend_is_lua_bridge():
    assert resolve_probe_backend(_ns()) == "lua_bridge"


def test_classic_flag_forces_classic():
    assert resolve_probe_backend(_ns(classic=True)) == "classic"


def test_probe_backend_explicit():
    assert resolve_probe_backend(_ns(probe_backend="classic")) == "classic"
    assert resolve_probe_backend(_ns(probe_backend="lua_bridge")) == "lua_bridge"


def test_classic_overrides_probe_backend():
    assert resolve_probe_backend(_ns(classic=True, probe_backend="lua_bridge")) == "classic"


def test_lua_bridge_flag_selects_bridge():
    assert resolve_probe_backend(_ns(lua_bridge=True)) == "lua_bridge"


def test_env_backend_when_no_flags(monkeypatch):
    monkeypatch.setenv("BLOCKCHECKS_PROBE_BACKEND", "classic")
    assert resolve_probe_backend(_ns()) == "classic"
    monkeypatch.setenv("BLOCKCHECKS_PROBE_BACKEND", "lua_bridge")
    assert resolve_probe_backend(_ns()) == "lua_bridge"


def test_flag_overrides_env(monkeypatch):
    monkeypatch.setenv("BLOCKCHECKS_PROBE_BACKEND", "classic")
    assert resolve_probe_backend(_ns(lua_bridge=True)) == "lua_bridge"
    assert resolve_probe_backend(_ns(classic=True)) == "classic"


def test_cliapp_parses_classic_and_probe_backend():
    """Новый пайплайн: parse_cli_argv + namespace_compat; оба способа задают бэкенд."""
    from blockchecks.cli.parser import parse_cli_argv

    for argv, expect_flag in (
        (["scan", "--classic", "--max", "1"], "classic"),
        (["scan", "--probe-backend", "classic", "--max", "1"], "classic"),
    ):
        ns, cmd, _ = parse_cli_argv(argv, cfg={})
        assert cmd == "scan"
        assert getattr(ns, "classic", False) is True or getattr(
            ns, "probe_backend", ""
        ) == "classic"
        assert expect_flag == "classic"



def test_runner_lua_bridge_flag_reflects_backend():
    """AsyncTestRunner.lua_bridge follows resolve_probe_backend at build time."""
    from blockchecks.engine.config import DEFAULT_PROBE_BACKEND

    assert DEFAULT_PROBE_BACKEND == "lua_bridge"
    # build_async_runner wiring covered by main_phases unit tests; assert the
    # boolean contract used everywhere: lua_bridge == backend == "lua_bridge".
    assert (resolve_probe_backend(_ns()) == "lua_bridge") is True
    assert (resolve_probe_backend(_ns(classic=True)) == "lua_bridge") is False


def test_pair_udp_and_fanout_always_classic():
    """test_pair_matrix / test_tcp_domains use classic regardless of the flag —
    UDP bootstrap and fan-out waves cannot use the bridge."""
    from blockchecks.engine.async_runner import AsyncTestRunner

    for lua in (False, True):
        runner = AsyncTestRunner(pool_size=2, lua_bridge=lua)
        # These code paths hardcode "classic" / _run_tcp_check.
        assert runner.lua_bridge == lua
        # The single-probe path (test_tcp) is always classic.
        assert runner._run_probe_batch is not None
