"""Integration tests for blockcheckS core workflows."""
import os, sys, pytest, asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.nfqws2 import Nfqws2Manager
from engine.firewall import Firewall
from engine.config import PYTHON_BIN, NFQWS2_BIN


class TestNfqws2Foreground:
    def test_start_stop_config(self):
        """nfqws2 starts from config file and stops cleanly."""
        mgr = Nfqws2Manager(qnum=219)
        config = os.path.join(os.path.dirname(__file__), "..", "configs", "simple_fake__fake_ts.conf")
        mgr.start_config(config)
        assert mgr._pid is not None, "Should have PID"
        assert mgr._proc is not None, "Should have process"
        mgr.stop()
        assert mgr._pid is None, "PID cleared after stop"

    def test_start_stop_inline(self):
        """nfqws2 starts from inline strategy and stops cleanly."""
        mgr = Nfqws2Manager(qnum=218)
        mgr.start("fake:repeats=1", qnum=218)
        assert mgr._pid is not None, "Should have PID"
        mgr.stop()
        assert mgr._pid is None, "PID cleared"


class TestFirewallTracked:
    def test_add_cleanup_count(self):
        """iptables rules are added and cleaned up precisely."""
        fw = Firewall()
        fw.prepare_tcp(port=443, qnum=219)
        assert len(fw._rules) == 1
        fw.prepare_udp(ports="50004:50004", qnum=219)
        assert len(fw._rules) == 2
        fw.cleanup()
        assert len(fw._rules) == 0

    def test_queue_bypass_present(self):
        """All NFQUEUE rules include --queue-bypass."""
        fw = Firewall()
        fw.prepare_tcp(port=443, qnum=219)
        rule = fw._rules[0]
        assert "--queue-bypass" in rule, f"queue-bypass missing: {rule}"


class TestConfigPaths:
    def test_python_bin_exists(self):
        """PYTHON_BIN resolves to an existing file."""
        assert os.path.exists(PYTHON_BIN), f"PYTHON_BIN not found: {PYTHON_BIN}"

    def test_nfqws2_bin_exists(self):
        """NFQWS2_BIN resolves to an existing file."""
        assert os.path.exists(NFQWS2_BIN)


@pytest.mark.asyncio
async def test_async_runner_start_stop(runner):
    """Async runner starts and stops without error."""
    assert runner.pool._created, "Pool should be created"


@pytest.mark.asyncio
async def test_async_runner_tcp_check(runner):
    """TCP check on example.com returns a result."""
    from engine.async_runner import StrategyItem
    item = StrategyItem(label="test", strategy="fake:repeats=1")
    result = await runner.test_tcp(item, "example.com", timeout=3)
    assert result.domain == "example.com"
    assert not result.success  # DNS fails in test netns
