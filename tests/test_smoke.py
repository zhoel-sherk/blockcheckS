"""Smoke tests for blockcheckS core functionality."""

import os, sys, asyncio
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.nfqws2 import Nfqws2Manager
from engine.firewall import Firewall
from engine.config import PYTHON_BIN, NFQWS2_BIN


def test_nfqws2_foreground():
    """nfqws2 starts in foreground mode, returns PID, stops cleanly."""
    mgr = Nfqws2Manager(qnum=219)
    config = os.path.join(os.path.dirname(__file__), "..", "configs", "simple_fake__fake_ts.conf")
    try:
        mgr.start_config(config)
        assert mgr._pid is not None, "Should have PID"
        assert mgr._proc is not None, "Should have process"
    finally:
        mgr.stop()
        # After stop(), _proc may be None (killpg + wait succeeded)
        assert mgr._pid is None, "PID should be cleared"


def test_firewall_tracked_rules():
    """iptables rules are added and cleaned up precisely."""
    fw = Firewall()
    fw.prepare_tcp(port=443, qnum=209)
    assert len(fw._rules) == 1
    fw.prepare_udp(ports="50004:50004", qnum=209)
    assert len(fw._rules) == 2
    fw.cleanup()
    assert len(fw._rules) == 0


def test_config_paths():
    """Config module resolves paths without hardcoded /home/zhoel."""
    assert PYTHON_BIN.endswith("python") or "python3" in PYTHON_BIN
    assert NFQWS2_BIN.endswith("nfqws2")


async def test_async_runner_basic():
    """Async runner starts, tests one strategy, stops cleanly."""
    from engine.async_runner import AsyncTestRunner, StrategyItem
    runner = AsyncTestRunner(pool_size=1)
    await runner.start()
    try:
        item = StrategyItem(label="test", strategy="fake:repeats=1")
        result = await runner.test_tcp(item, "example.com", timeout=5)
        assert result.domain == "example.com"
    finally:
        await runner.stop()


if __name__ == "__main__":
    test_nfqws2_foreground()
    print("PASS test_nfqws2_foreground")
    test_firewall_tracked_rules()
    print("PASS test_firewall_tracked_rules")
    test_config_paths()
    print("PASS test_config_paths")
    asyncio.run(test_async_runner_basic())
    print("PASS test_async_runner_basic")
