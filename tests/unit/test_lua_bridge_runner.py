"""AsyncTestRunner lua-bridge wiring."""

from __future__ import annotations

import pytest

from blockchecks.engine.async_runner import AsyncTestRunner


@pytest.mark.unit
def test_async_runner_lua_bridge_flags() -> None:
    runner = AsyncTestRunner(
        pool_size=2,
        lua_bridge=True,
        bridge_batch=100,
        lua_bridge_compare=True,
        lua_extra=["/tmp/custom.lua"],
    )
    assert runner.lua_bridge is True
    assert runner.bridge_batch == 100
    assert runner.lua_bridge_compare is True
    assert runner.lua_extra == ["/tmp/custom.lua"]
    assert runner._next_probe_gen() == 1
