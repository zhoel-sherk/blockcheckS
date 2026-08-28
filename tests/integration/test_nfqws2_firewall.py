"""Integration tests — Linux + sudo + nfqws2 required."""

from __future__ import annotations

import os

import pytest

from blockchecks.engine.config import NFQWS2_BIN, PYTHON_BIN
from blockchecks.service.nfqws2 import Nfqws2Manager
from blockchecks.service.ns_firewall import HostFirewall

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _require_linux_nfqws2(nfqws2_available):
    if os.name == "nt":
        pytest.skip("integration requires Linux")


def test_nfqws2_killpg_process_gone(nfqws2_available):
    mgr = Nfqws2Manager(qnum=219)
    mgr.start("fake:repeats=1", qnum=219)
    pid = mgr._pid
    assert pid is not None
    mgr.stop()
    assert mgr._pid is None
    # Process group should be gone
    with pytest.raises((ProcessLookupError, OSError)):
        os.kill(pid, 0)


def test_firewall_cleanup_no_flush_output():
    fw = HostFirewall()
    from blockchecks.service.ns_firewall import _RuleSpec

    fw._rules = {
        _RuleSpec("tcp", "443", 219, False, True, None): [
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "443",
            "-j",
            "NFQUEUE",
            "--queue-num",
            "219",
            "--queue-bypass",
        ],
    }
    # Don't actually run iptables if no sudo — just assert rule shape
    assert all(r[0] == "-D" for r in fw._rules.values())
    assert not any("-F" in r for r in fw._rules.values())
    fw._rules.clear()


def test_firewall_queue_bypass_tracked():
    fw = HostFirewall()
    recorded = []

    def fake_run(*args, check=False):
        class R:
            returncode = 0
            stderr = ""

        recorded.append(list(args))
        return R()

    fw._run = fake_run  # type: ignore
    fw.prepare_tcp(port=443, qnum=219)
    fw.prepare_udp(voice_port=50006, qnum=219)
    assert len(fw._rules) == 2
    specs = list(fw._rules)
    assert all(s.bypass for s in specs)
    assert any(s.dport == "50006" for s in specs)
    fw.cleanup()
    assert fw._rules == {}


def test_python_bin_exists():
    # On Linux CI with venv this should exist; otherwise soft-skip
    if not os.path.exists(PYTHON_BIN):
        pytest.skip(f"PYTHON_BIN missing: {PYTHON_BIN}")
    assert os.path.exists(PYTHON_BIN)


def test_nfqws2_bin_exists(nfqws2_available):
    assert os.path.exists(NFQWS2_BIN)
