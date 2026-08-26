"""Unit tests for NsFirewall — tracked attach/detach without -F OUTPUT."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from blockchecks.service.ns_firewall import (
    IptablesError,
    NsFirewall,
    drop_ns_firewall,
    get_ns_firewall,
    mark_ns_dirty,
    reset_registry_for_tests,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clear_registry():
    reset_registry_for_tests()
    yield
    reset_registry_for_tests()


def test_attach_tracks_delete_and_skips_duplicate():
    fw = NsFirewall("bs-p0")
    runs: list[list[str]] = []

    def fake_run(*args, check=False):
        runs.append(list(args))
        return MagicMock(returncode=0, stderr="", stdout="")

    with patch.object(fw, "_run", side_effect=fake_run):
        fw.attach(proto="tcp", port="443", queue=200)
        fw.attach(proto="tcp", port="443", queue=200)

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
        ],
        [
            "-C",
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
        ],
    ]
    assert fw.is_attached(proto="tcp", port="443", queue=200)


def test_attach_multiport_udp():
    fw = NsFirewall("bs-p0")
    with patch.object(fw, "_run", return_value=MagicMock(returncode=0, stderr="", stdout="")) as run:
        fw.attach(proto="udp", port="50000:50100", queue=201, multiport=True)
    assert "-m" in run.call_args_list[0].args
    assert "multiport" in run.call_args_list[0].args


def test_detach_issues_matching_deletes():
    fw = NsFirewall("bs-p0")
    deletes: list[tuple] = []

    def fake_run(*args, check=False):
        deletes.append((args, check))
        return MagicMock(returncode=0, stderr="", stdout="")

    from blockchecks.service.ns_firewall import _RuleSpec

    spec = _RuleSpec("tcp", "443", 200)
    fw._rules[spec] = ["-D", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "NFQUEUE"]
    with patch.object(fw, "_run", side_effect=fake_run):
        fw.detach()

    assert deletes == [
        (("-D", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "NFQUEUE"), False)
    ]
    assert fw._rules == {}


def test_dirty_attach_resyncs():
    from blockchecks.service.ns_firewall import _RuleSpec

    fw = NsFirewall("bs-p0")
    spec = _RuleSpec("tcp", "443", 200)
    fw._rules[spec] = ["-D", "OUTPUT", "x"]
    fw.mark_dirty()

    calls: list[str] = []

    def fake_run(*args, check=False):
        calls.append(args[0])
        return MagicMock(returncode=0, stderr="", stdout="")

    with patch.object(fw, "_run", side_effect=fake_run):
        fw.attach(proto="tcp", port="443", queue=200)

    assert calls[0] == "-D"
    assert "-A" in calls


def test_attach_raises_when_verify_fails():
    fw = NsFirewall("bs-p0")

    def fake_run(*args, check=False):
        if args and args[0] == "-C":
            return MagicMock(returncode=1, stderr="missing", stdout="")
        return MagicMock(returncode=0, stderr="", stdout="")

    with patch.object(fw, "_run", side_effect=fake_run), pytest.raises(IptablesError):
        fw.attach(proto="tcp", port="443", queue=200)


def test_registry_get_and_drop():
    a = get_ns_firewall("bs-p0")
    b = get_ns_firewall("bs-p0")
    assert a is b
    with patch.object(a, "detach") as detach:
        drop_ns_firewall("bs-p0")
    detach.assert_called_once()
    assert get_ns_firewall("bs-p0") is not a


def test_mark_ns_dirty_on_existing():
    fw = get_ns_firewall("bs-p0")
    mark_ns_dirty("bs-p0")
    assert fw.dirty is True


def test_context_manager_detaches():
    fw = NsFirewall("bs-p0")
    with patch.object(fw, "detach") as detach:
        with fw:
            pass
    detach.assert_called_once()
