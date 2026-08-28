"""Unit tests for HostFirewall — tracked -A/-D and cleanup-on-exception."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

from blockchecks.service.ns_firewall import HostFirewall

pytestmark = pytest.mark.unit


def test_prepare_tcp_tracks_delete_rule_with_bypass():
    fw = HostFirewall()
    runs: list[list[str]] = []

    def fake_run(*args, check=False):
        runs.append(list(args))
        return MagicMock(returncode=0, stderr="")

    with patch.object(fw, "_run", side_effect=fake_run):
        fw.prepare_tcp(port=443, qnum=200)

    assert runs[0] == [
        "-A",
        "OUTPUT",
        "-p",
        "tcp",
        "--dport",
        "443",
        "-j",
        "NFQUEUE",
        "--queue-num",
        "200",
        "--queue-bypass",
    ]
    assert runs[1][0] == "-C"
    assert fw._rules
    spec = next(iter(fw._rules))
    assert spec.proto == "tcp"
    assert spec.dport == "443"
    assert spec.queue == 200
    assert spec.bypass


def test_prepare_tcp_with_dst_ip():
    fw = HostFirewall()
    with patch.object(fw, "_run", return_value=MagicMock(returncode=0, stderr="")) as run:
        fw.prepare_tcp(port=443, qnum=200, dst_ip="1.2.3.4")
    args = run.call_args.args
    assert "-d" in args
    assert "1.2.3.4" in args
    spec = next(iter(fw._rules))
    assert spec.dst_ip == "1.2.3.4"
    assert spec.bypass


def test_cleanup_issues_matching_deletes_and_clears():
    fw = HostFirewall()
    deletes: list[tuple] = []

    def fake_run(*args, check=False):
        deletes.append((args, check))
        return MagicMock(returncode=0, stderr="")

    from blockchecks.service.ns_firewall import _RuleSpec

    fw._rules = {
        _RuleSpec("tcp", "443", 200, False, True, None): [
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "443",
            "-j",
            "NFQUEUE",
        ],
        _RuleSpec("udp", "50004", 201, False, True, None): [
            "-D",
            "OUTPUT",
            "-p",
            "udp",
            "--dport",
            "50004",
            "-j",
            "NFQUEUE",
        ],
    }
    with patch.object(fw, "_run", side_effect=fake_run):
        fw.cleanup()

    assert [d[0] for d in deletes] == [
        ("-D", "OUTPUT", "-p", "udp", "--dport", "50004", "-j", "NFQUEUE"),
        ("-D", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "NFQUEUE"),
    ]
    assert all(d[1] is False for d in deletes)
    assert fw._rules == {}


def test_context_manager_cleanup_on_exception():
    fw = HostFirewall()
    cleaned = {"n": 0}

    def fake_detach():
        cleaned["n"] += 1
        fw._rules.clear()

    fw.prepare_tcp = MagicMock()  # type: ignore[method-assign]
    fw.detach = fake_detach  # type: ignore[method-assign]
    from blockchecks.service.ns_firewall import _RuleSpec

    fw._rules = {_RuleSpec("tcp", "443", 200): ["-D", "OUTPUT", "x"]}

    with pytest.raises(RuntimeError, match="boom"):
        with fw:
            raise RuntimeError("boom")

    assert cleaned["n"] == 1


def test_prepare_udp_single_voice_port():
    fw = HostFirewall()
    with patch.object(fw, "_run", return_value=MagicMock(returncode=0, stderr="")) as run:
        fw.prepare_udp(voice_port=50004, qnum=201)
    args = run.call_args.args
    assert "--dport" in args
    assert "50004" in args
    assert "--queue-num" in args
    assert "201" in args
    assert "--queue-bypass" in args


def test_cmd_prefix_host_only():
    fw = HostFirewall()
    assert fw._cmd_prefix() == ["sudo", "-n", "iptables"]


def test_cleanup_logs_on_delete_failure(caplog):
    fw = HostFirewall()
    from blockchecks.service.ns_firewall import _RuleSpec

    fw._rules = {
        _RuleSpec("tcp", "443", 200): [
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "443",
            "-j",
            "NFQUEUE",
        ],
    }
    with patch.object(fw, "_run", side_effect=OSError("no iptables")):
        with caplog.at_level(logging.WARNING, logger="blockchecks.service.ns_firewall"):
            fw.cleanup()
    assert fw._rules == {}
    assert any("detach" in r.message and "failed" in r.message for r in caplog.records)
