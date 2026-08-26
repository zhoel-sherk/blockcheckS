"""Tests for nfqws2 settle / readiness poll."""

from unittest.mock import MagicMock, patch

import pytest

from blockchecks.service.nfqws2_settle import (
    nfqws2_running_in_ns,
    wait_nfqws2_ready,
)


def test_nfqws2_running_in_ns_true():
    with patch("blockchecks.service.metrics.find_nfqws2_pids", return_value=[123]):
        assert nfqws2_running_in_ns("bs-p0") is True


def test_nfqws2_running_in_ns_false():
    with patch("blockchecks.service.metrics.find_nfqws2_pids", return_value=[]):
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


def test_wait_min_wait_floor():
    """Min_wait dominates the deadline — no busy-loop, returns after min_wait."""
    t = {"now": 0.0}

    def fake_perf():
        return t["now"]

    def fake_sleep(dt):
        t["now"] += dt

    with patch("blockchecks.service.nfqws2_settle.nfqws2_running_in_ns", return_value=False):
        with patch("blockchecks.service.nfqws2_settle.time.sleep", side_effect=fake_sleep):
            with patch(
                "blockchecks.service.nfqws2_settle.time.perf_counter", side_effect=fake_perf
            ):
                elapsed = wait_nfqws2_ready("bs-p0", max_wait=0.1, poll_interval=0.05, min_wait=0.5)
    assert elapsed >= 0.5


def test_wait_nfqws2_ready_min_procs_two():
    counts = MagicMock(side_effect=[1, 2])
    sleep = MagicMock()
    with patch("blockchecks.service.nfqws2_settle.nfqws2_count_in_ns", counts):
        with patch("blockchecks.service.nfqws2_settle.time.sleep", sleep):
            elapsed = wait_nfqws2_ready(
                "bs-p0", max_wait=1.0, poll_interval=0.1, min_wait=0, min_procs=2
            )
    assert counts.call_count == 2
    assert 0 <= elapsed < 1.0


def test_wait_nfqws2_gone_returns_true_when_never_there():
    """_wait_nfqws2_gone: nfqws2 absent → returns True immediately."""
    from blockchecks.service.nfqws2_settle import _wait_nfqws2_gone

    running = MagicMock(return_value=False)
    with patch("blockchecks.service.nfqws2_settle.nfqws2_running_in_ns", running):
        assert _wait_nfqws2_gone("bs-p0", max_wait=0.5) is True


def test_wait_nfqws2_gone_polls_until_gone():
    """pkill is async; _wait_nfqws2_gone polls until the daemon disappears."""
    from blockchecks.service.nfqws2_settle import _wait_nfqws2_gone

    running = MagicMock(side_effect=[True, True, False])
    sleep = MagicMock()
    with patch("blockchecks.service.nfqws2_settle.nfqws2_running_in_ns", running):
        with patch("blockchecks.service.nfqws2_settle.time.sleep", sleep):
            assert _wait_nfqws2_gone("bs-p0", max_wait=1.0, poll_interval=0.05) is True
    assert running.call_count == 3


def test_wait_nfqws2_gone_timeout():
    """If nfqws2 never disappears within max_wait, return False (caller decides)."""
    from blockchecks.service.nfqws2_settle import _wait_nfqws2_gone

    running = MagicMock(return_value=True)
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
                assert _wait_nfqws2_gone("bs-p0", max_wait=0.3, poll_interval=0.1) is False


def test_nfqws2_pid_in_ns():
    from blockchecks.service.nfqws2_settle import nfqws2_pid_in_ns

    with patch("blockchecks.service.metrics.find_nfqws2_pids", return_value=[42, 99]):
        assert nfqws2_pid_in_ns(42, "bs-p0") is True
        assert nfqws2_pid_in_ns(1, "bs-p0") is False


def test_nfqws2_out_shows_bind(tmp_path):
    from blockchecks.service.nfqws2_settle import nfqws2_out_shows_bind

    logf = tmp_path / "out.log"
    logf.write_text("nfqws2 init\n", encoding="utf-8")
    assert nfqws2_out_shows_bind(logf) is False
    logf.write_text("setting copy_packet mode\n", encoding="utf-8")
    assert nfqws2_out_shows_bind(logf) is True


def test_wait_nfqws2_bind_proof_out_marker(tmp_path):
    from blockchecks.service.nfqws2_settle import wait_nfqws2_bind_proof

    logf = tmp_path / "out.log"
    logf.write_text("setting copy_packet mode\n", encoding="utf-8")
    with patch("blockchecks.service.nfqws2_settle.time.sleep"):
        assert wait_nfqws2_bind_proof("bs-p0", out_path=logf, within=0.1) is True


def test_wait_nfqws2_bind_proof_pid(tmp_path):
    from blockchecks.service.nfqws2_settle import wait_nfqws2_bind_proof

    calls = {"n": 0}

    def pid_ready(pid, ns):
        calls["n"] += 1
        return calls["n"] >= 2

    with (
        patch("blockchecks.service.nfqws2_settle.nfqws2_pid_in_ns", side_effect=pid_ready),
        patch("blockchecks.service.nfqws2_settle.time.sleep"),
    ):
        assert wait_nfqws2_bind_proof("bs-p0", launched_pid=123, within=0.5) is True


@pytest.mark.parametrize(
    ("out_txt", "expected"),
    [
        ("nfq_create_queue(): Operation not permitted\n", True),
        ("nfq_create_queue(): some other error\n", False),
        ("Operation not permitted\n", False),
        ("SSL error code 35\n", False),
        ("setting copy_packet mode\n", False),
        ("", False),
    ],
)
def test_nfqws2_out_shows_bind_busy(out_txt, expected):
    from blockchecks.service.nfqws2_settle import nfqws2_out_shows_bind_busy

    assert nfqws2_out_shows_bind_busy(out_txt) is expected


@pytest.mark.parametrize(
    ("out_txt", "drain_ok", "succeeded", "attempt", "max_attempts", "expected"),
    [
        ("nfq_create_queue(): Operation not permitted\n", True, False, 1, 5, (True, "queue busy")),
        ("", False, False, 1, 5, (True, "pkill drain incomplete")),
        ("SSL error code 35\n", True, False, 1, 5, (False, None)),
        ("nfq_create_queue(): Operation not permitted\n", True, True, 1, 5, (False, None)),
        ("nfq_create_queue(): Operation not permitted\n", True, False, 5, 5, (False, None)),
        ("nfq_create_queue(): Operation not permitted\n", True, False, 3, 5, (True, "queue busy")),
    ],
)
def test_nfqws2_bind_retry_should_continue(
    out_txt, drain_ok, succeeded, attempt, max_attempts, expected
):
    from blockchecks.service.nfqws2_settle import nfqws2_bind_retry_should_continue

    assert (
        nfqws2_bind_retry_should_continue(
            out_txt,
            attempt=attempt,
            max_attempts=max_attempts,
            drain_ok=drain_ok,
            succeeded=succeeded,
        )
        == expected
    )


def test_nfqws2_bind_retry_backoff():
    from blockchecks.service.nfqws2_settle import nfqws2_bind_retry_backoff

    assert nfqws2_bind_retry_backoff(1) == 2.0
    assert nfqws2_bind_retry_backoff(2) == 4.0
    assert nfqws2_bind_retry_backoff(3) == 6.0
    assert nfqws2_bind_retry_backoff(10) == 6.0
