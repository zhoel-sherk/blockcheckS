"""Unit tests for NsFirewall bypass/detach_one and in_ns_workers integration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from blockchecks.service.ns_firewall import NsFirewall, reset_registry_for_tests

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clear_registry():
    reset_registry_for_tests()
    yield
    reset_registry_for_tests()


def test_attach_without_bypass():
    fw = NsFirewall("bs-p0")
    runs: list[list[str]] = []

    def fake_run(*args, check=False):
        runs.append(list(args))
        return MagicMock(returncode=0, stderr="", stdout="")

    with patch.object(fw, "_run", side_effect=fake_run):
        fw.attach(proto="udp", port="50004", queue=201, bypass=False)

    assert "--queue-bypass" not in runs[0]
    assert fw.is_attached(proto="udp", port="50004", queue=201, bypass=False)
    assert not fw.is_attached(proto="udp", port="50004", queue=201, bypass=True)


def test_detach_one_leaves_other_rules():
    fw = NsFirewall("bs-p0")
    deletes: list[tuple] = []

    def fake_run(*args, check=False):
        deletes.append(args)
        return MagicMock(returncode=0, stderr="", stdout="")

    with patch.object(fw, "_run", side_effect=fake_run):
        fw.attach(proto="tcp", port="443", queue=200, bypass=True)
        fw.attach(proto="udp", port="50004", queue=201, bypass=False)
        fw.detach_one(proto="udp", port="50004", queue=201, bypass=False)

    assert fw.is_attached(proto="tcp", port="443", queue=200, bypass=True)
    assert not fw.is_attached(proto="udp", port="50004", queue=201, bypass=False)
    assert deletes[-1][0] == "-D"
    assert "--queue-bypass" not in deletes[-1]


def test_tcp_check_detaches_in_finally():
    from blockchecks.service.in_ns_workers import _run_tcp_check

    fw = MagicMock()
    with (
        patch("blockchecks.service.nfqws2.start_daemon", return_value=0.05),
        patch("blockchecks.service.ns_firewall.get_ns_firewall", return_value=fw),
        patch("blockchecks.service.in_ns_workers._pkill_nfqws2"),
        patch(
            "blockchecks.service.probe.invoke_curl_probe_worker",
            return_value={"success": True, "http_code": 200},
        ),
        patch("blockchecks.service.in_ns_workers.is_googlevideo_domain", return_value=False),
        patch("blockchecks.service.in_ns_workers.is_ytcdn_domain", return_value=False),
    ):
        _run_tcp_check("bs-p0", "fake:blob=stun:repeats=6", "discord.com", 5.0)

    fw.attach.assert_called_once_with(proto="tcp", port="443", queue=200, bypass=True)
    fw.detach_one.assert_called_once_with(proto="tcp", port="443", queue=200, bypass=True)


def test_udp_coexist_does_not_flush_tcp():
    from blockchecks.service.in_ns_workers import _attach_udp_queue

    fw = MagicMock()
    with patch("blockchecks.service.ns_firewall.get_ns_firewall", return_value=fw):
        _attach_udp_queue("bs-p0", 50004, coexist=True)

    fw.detach.assert_not_called()
    fw.attach.assert_called_once_with(proto="udp", port="50004", queue=201, bypass=False)


def test_udp_non_coexist_detaches_before_attach():
    from blockchecks.service.in_ns_workers import _attach_udp_queue

    fw = MagicMock()
    with patch("blockchecks.service.ns_firewall.get_ns_firewall", return_value=fw):
        _attach_udp_queue("bs-p0", 50004, coexist=False)

    fw.detach.assert_called_once()
    fw.attach.assert_called_once_with(proto="udp", port="50004", queue=201, bypass=False)


def test_quic_check_no_flush_uses_ns_firewall():
    from blockchecks.service.in_ns_workers import _run_quic_check

    fw = MagicMock()
    with (
        patch("blockchecks.service.nfqws2.start_daemon", return_value=0.05),
        patch("blockchecks.service.ns_firewall.get_ns_firewall", return_value=fw),
        patch("blockchecks.service.in_ns_workers._pkill_nfqws2"),
        patch(
            "blockchecks.checkers.http3.quic_subprocess_result",
            return_value={"success": True},
        ),
    ):
        _run_quic_check("bs-p0", "fake:quic", "discord.com", 5.0)

    fw.attach.assert_called_once_with(proto="udp", port="443", queue=201, bypass=True)
    fw.detach_one.assert_called_once_with(proto="udp", port="443", queue=201, bypass=True)
    assert not any(
        "-F" in str(c)
        for c in (fw.attach.call_args_list + fw.detach_one.call_args_list)
    )
