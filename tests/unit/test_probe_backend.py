"""Campaign probe backend is lua_bridge; --classic warns and maps."""

from __future__ import annotations

from argparse import Namespace

import pytest

from blockchecks.engine.config import DEFAULT_PROBE_BACKEND, resolve_probe_backend

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
    assert DEFAULT_PROBE_BACKEND == "lua_bridge"


def test_classic_flag_maps_to_lua_bridge(caplog):
    assert resolve_probe_backend(_ns(classic=True)) == "lua_bridge"
    assert "deprecated" in caplog.text.lower() or "mapping to lua_bridge" in caplog.text


def test_probe_backend_classic_maps(caplog):
    assert resolve_probe_backend(_ns(probe_backend="classic")) == "lua_bridge"
    assert "lua_bridge" in caplog.text or "deprecated" in caplog.text.lower()


def test_probe_backend_lua_bridge_explicit():
    assert resolve_probe_backend(_ns(probe_backend="lua_bridge")) == "lua_bridge"


def test_lua_bridge_flag_selects_bridge():
    assert resolve_probe_backend(_ns(lua_bridge=True)) == "lua_bridge"


def test_env_classic_maps_to_lua_bridge(monkeypatch, caplog):
    monkeypatch.setenv("BLOCKCHECKS_PROBE_BACKEND", "classic")
    assert resolve_probe_backend(_ns()) == "lua_bridge"
    assert "mapping to lua_bridge" in caplog.text


def test_env_lua_bridge(monkeypatch):
    monkeypatch.setenv("BLOCKCHECKS_PROBE_BACKEND", "lua_bridge")
    assert resolve_probe_backend(_ns()) == "lua_bridge"


def test_cliapp_parses_deprecated_classic():
    from blockchecks.cli.parser import parse_cli_argv

    ns, cmd, _ = parse_cli_argv(["scan", "--classic", "--max", "1"], cfg={})
    assert cmd == "scan"
    assert ns.classic is True
    assert resolve_probe_backend(ns) == "lua_bridge"


def test_tcp_udp_help_has_no_backend_flags():
    from blockchecks.cli.parser import iter_subparsers

    subs = iter_subparsers()
    tcp_opts = {o for a in subs["tcp"]._actions for o in a.option_strings}
    udp_opts = {o for a in subs["udp"]._actions for o in a.option_strings}
    for flag in ("--classic", "--probe-backend", "--lua-bridge"):
        assert flag not in tcp_opts
        assert flag not in udp_opts


def test_lua_bridge_compare_not_on_cli():
    from blockchecks.cli.parser import iter_subparsers

    scan_opts = {o for a in iter_subparsers()["scan"]._actions for o in a.option_strings}
    assert "--lua-bridge-compare" not in scan_opts


def test_fanout_and_oneshot_still_exist():
    from blockchecks.engine.async_runner import AsyncTestRunner

    runner = AsyncTestRunner(pool_size=2, lua_bridge=True)
    assert runner.test_tcp_domains is not None
    assert runner._run_probe_batch is not None
