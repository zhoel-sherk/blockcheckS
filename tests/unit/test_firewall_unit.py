"""Unit tests for Firewall — tracked -A/-D and cleanup-on-exception."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from blockchecks.engine.firewall import Firewall

pytestmark = pytest.mark.unit


def test_prepare_tcp_tracks_delete_rule_with_bypass():
    fw = Firewall(ns_name="bs-p0")
    runs: list[list[str]] = []

    def fake_run(*args, check=False):
        runs.append(list(args))
        return MagicMock(returncode=0, stderr="")

    with patch.object(fw, "_run", side_effect=fake_run):
        fw.prepare_tcp(port=443, qnum=200)

    assert runs == [
        [
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
    ]
    assert fw._rules == [
        [
            "-D",
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
    ]


def test_prepare_tcp_with_dst_ip():
    fw = Firewall()
    with patch.object(fw, "_run", return_value=MagicMock(returncode=0, stderr="")) as run:
        fw.prepare_tcp(port=443, qnum=200, dst_ip="1.2.3.4")
    assert "-d" in run.call_args.args
    assert "1.2.3.4" in run.call_args.args
    assert fw._rules[0][0] == "-D"
    assert "--queue-bypass" in fw._rules[0]


def test_cleanup_issues_matching_deletes_and_clears():
    fw = Firewall(ns_name="bs-p0")
    deletes: list[tuple] = []

    def fake_run(*args, check=False):
        deletes.append((args, check))
        return MagicMock(returncode=0, stderr="")

    fw._rules = [
        ["-D", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "NFQUEUE"],
        ["-D", "OUTPUT", "-p", "udp", "--dport", "50004", "-j", "NFQUEUE"],
    ]
    with patch.object(fw, "_run", side_effect=fake_run):
        fw.cleanup()

    assert [d[0] for d in deletes] == [
        ("-D", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "NFQUEUE"),
        ("-D", "OUTPUT", "-p", "udp", "--dport", "50004", "-j", "NFQUEUE"),
    ]
    assert all(d[1] is False for d in deletes)
    assert fw._rules == []


def test_context_manager_cleanup_on_exception():
    fw = Firewall()
    cleaned = {"n": 0}

    def fake_cleanup():
        cleaned["n"] += 1
        fw._rules.clear()

    fw.prepare_tcp = MagicMock()  # type: ignore[method-assign]
    fw.cleanup = fake_cleanup  # type: ignore[method-assign]
    fw._rules = [["-D", "OUTPUT", "x"]]

    with pytest.raises(RuntimeError, match="boom"):
        with fw:
            raise RuntimeError("boom")

    assert cleaned["n"] == 1


def test_prepare_udp_single_voice_port():
    fw = Firewall()
    with patch.object(fw, "_run", return_value=MagicMock(returncode=0, stderr="")) as run:
        fw.prepare_udp(voice_port=50004, qnum=201)
    args = run.call_args.args
    assert "--dport" in args
    assert "50004" in args
    assert "--queue-num" in args
    assert "201" in args
    assert "--queue-bypass" in args


def test_ns_prefix_includes_netns_exec():
    fw = Firewall(ns_name="bs-p3")
    assert fw._ns_prefix() == ["sudo", "ip", "netns", "exec", "bs-p3"]
    assert Firewall()._ns_prefix() == ["sudo"]
