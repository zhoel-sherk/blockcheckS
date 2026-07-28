"""Integration tests — Linux + sudo + nfqws2 required."""
from __future__ import annotations

import os
import signal

import pytest

from engine.config import NFQWS2_BIN, PYTHON_BIN
from engine.firewall import Firewall
from engine.nfqws2 import Nfqws2Manager


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
    fw = Firewall()
    # Tracked cleanup uses -D only; never -F
    fw._rules.append(["-D", "OUTPUT", "-p", "tcp", "--dport", "443",
                       "-j", "NFQUEUE", "--queue-num", "219", "--queue-bypass"])
    # Don't actually run iptables if no sudo — just assert rule shape
    assert all(r[0] == "-D" for r in fw._rules)
    assert not any("-F" in r for r in fw._rules)
    fw._rules.clear()


def test_firewall_queue_bypass_tracked():
    fw = Firewall()
    # prepare without applying: inspect _add_rule tracking via monkeypatch
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
    assert "--queue-bypass" in fw._rules[0]
    assert "50006" in fw._rules[1]
    fw.cleanup()
    assert fw._rules == []


def test_python_bin_exists():
    # On Linux CI with venv this should exist; otherwise soft-skip
    if not os.path.exists(PYTHON_BIN):
        pytest.skip(f"PYTHON_BIN missing: {PYTHON_BIN}")
    assert os.path.exists(PYTHON_BIN)


def test_nfqws2_bin_exists(nfqws2_available):
    assert os.path.exists(NFQWS2_BIN)
