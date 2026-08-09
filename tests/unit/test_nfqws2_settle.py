"""Unit tests for nfqws2 settle readiness poll (Phase 11 B1)."""

from unittest.mock import MagicMock, patch

from blockchecks.service.nfqws2_settle import (
    nfqws2_running_in_ns,
    wait_nfqws2_ready,
)


def test_nfqws2_running_in_ns_true():
    mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="123\n"))
    with patch("blockchecks.service.nfqws2_settle.sp.run", mock_run):
        assert nfqws2_running_in_ns("bs-p0") is True


def test_nfqws2_running_in_ns_false():
    mock_run = MagicMock(return_value=MagicMock(returncode=1, stdout=""))
    with patch("blockchecks.service.nfqws2_settle.sp.run", mock_run):
        assert nfqws2_running_in_ns("bs-p0") is False


def test_wait_nfqws2_ready_returns_early():
    running = MagicMock(side_effect=[False, True])
    sleep = MagicMock()
    with patch("blockchecks.service.nfqws2_settle.nfqws2_running_in_ns", running):
        with patch("blockchecks.service.nfqws2_settle.time.sleep", sleep):
            elapsed = wait_nfqws2_ready("bs-p0", max_wait=1.0, poll_interval=0.1, min_wait=0)
    assert running.call_count == 2
    assert sleep.call_count == 1
    assert sleep.call_args.args == (0.1,)
    assert 0 <= elapsed < 1.0


def test_wait_nfqws2_ready_timeout():
    running = MagicMock(return_value=False)
    sleep = MagicMock()
    t = {"now": 0.0}

    def fake_perf():
        return t["now"]

    def fake_sleep(dt):
        t["now"] += dt

    with patch("blockchecks.service.nfqws2_settle.nfqws2_running_in_ns", running):
        with patch("blockchecks.service.nfqws2_settle.time.sleep", side_effect=fake_sleep):
            with patch(
                "blockchecks.service.nfqws2_settle.time.perf_counter",
                side_effect=fake_perf,
            ):
                elapsed = wait_nfqws2_ready("bs-p0", max_wait=0.3, poll_interval=0.1, min_wait=0)
    assert running.call_count >= 2
    assert elapsed >= 0.3
    assert sleep.call_count >= 2 or running.call_count >= 3


def test_apply_gp_protocol_flags():
    from argparse import Namespace

    from blockchecks.main_phases import apply_gp_protocol_flags as _apply_gp_protocol_flags

    args = Namespace(protocol="tls12", no_http=False, no_quic=False)
    args.http_off = True
    args.http3_off = True
    args.tls12_off = False
    args.tls13_off = False
    skip = _apply_gp_protocol_flags(args)
    assert args.no_http is True
    assert args.no_quic is True
    assert skip is False

    args.tls12_off = True
    assert _apply_gp_protocol_flags(args) is True
