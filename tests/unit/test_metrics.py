"""Unit tests for services.metrics (MemoryMonitor / leak slope)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from blockchecks.engine.services.metrics import (
    MemoryMonitor,
    MemorySample,
    compute_leak_slope,
    find_nfqws2_pids,
    process_rss_bytes,
)

pytestmark = pytest.mark.unit


def test_leak_slope_zero_for_short_window():
    assert compute_leak_slope([]) == 0.0
    assert compute_leak_slope([MemorySample(1.0, 1024 * 1024)]) == 0.0


def test_leak_slope_positive_for_growth():
    samples = [
        MemorySample(100.0, 100 * 1024 * 1024),
        MemorySample(101.0, 150 * 1024 * 1024),
        MemorySample(102.0, 200 * 1024 * 1024),
    ]
    slope = compute_leak_slope(samples)
    # 50 MiB per second
    assert 49.0 < slope < 51.0


def test_leak_slope_zero_for_flat():
    samples = [MemorySample(float(i), 64 * 1024 * 1024) for i in range(5)]
    assert abs(compute_leak_slope(samples)) < 1e-6


def test_process_rss_returns_zero_on_error():
    with patch("blockchecks.engine.services.metrics.process_rss_bytes", return_value=0):
        assert process_rss_bytes(999999) == 0


def test_find_nfqws2_pids_matches_netns_inode():
    """psutil path: only nfqws2 whose /proc ns/net inode equals the ns file inode."""
    fake_procs = []
    for pid in (1234, 5678):
        p = MagicMock()
        p.pid = pid
        p.info = {"name": "nfqws2"}
        fake_procs.append(p)

    def _readlink(path):
        if "/1234/" in path:
            return "net:[99]"
        if "/5678/" in path:
            return "net:[100]"
        raise OSError("not found")

    with (
        patch("blockchecks.engine.services.metrics.os.stat") as mock_stat,
        patch("blockchecks.engine.services.metrics.os.readlink", side_effect=_readlink),
        patch("psutil.process_iter", return_value=iter(fake_procs)),
    ):
        mock_stat.return_value.st_ino = 99
        assert find_nfqws2_pids("bs-p0") == [1234]


def test_find_nfqws2_pids_missing_ns_file():
    with patch("blockchecks.engine.services.metrics.os.stat", side_effect=OSError):
        assert find_nfqws2_pids("bs-p0") == []


def test_find_nfqws2_pids_skips_non_nfqws2():
    p = MagicMock()
    p.pid = 777
    p.info = {"name": "nginx"}
    with (
        patch("blockchecks.engine.services.metrics.os.stat") as mock_stat,
        patch("psutil.process_iter", return_value=iter([p])),
    ):
        mock_stat.return_value.st_ino = 99
        assert find_nfqws2_pids("bs-p0") == []


def test_monitor_flags_rss_ceiling():
    mon = MemoryMonitor(enabled=True, max_mib=100, window=20)
    with patch("blockchecks.engine.services.metrics.process_rss_bytes", return_value=200 * 1024 * 1024):
        mon.record_pid(42)
        cands = mon.recycle_candidates()
    assert cands == [(42, "rss=200MiB > 100MiB")]


def test_monitor_flags_leak_slope():
    mon = MemoryMonitor(enabled=True, max_mib=1000, leak_slope=8, window=20)
    seq = [100 * 1024 * 1024, 200 * 1024 * 1024, 300 * 1024 * 1024, 400 * 1024 * 1024]
    with patch("blockchecks.engine.services.metrics.time.monotonic", side_effect=[1, 2, 3, 4]):
        with patch("blockchecks.engine.services.metrics.process_rss_bytes", side_effect=seq):
            for _ in seq:
                mon.record_pid(7)
    cands = mon.recycle_candidates()
    assert len(cands) == 1
    assert cands[0][0] == 7
    assert "leak=" in cands[0][1]


def test_monitor_clear_resets_window():
    mon = MemoryMonitor(enabled=True, max_mib=100, window=20)
    with patch("blockchecks.engine.services.metrics.process_rss_bytes", return_value=500 * 1024 * 1024):
        mon.record_pid(9)
        mon.clear(9)
        mon.clear()  # clear-all path
    assert mon.recycle_candidates() == []


def test_monitor_disabled_skips_sampling():
    mon = MemoryMonitor(enabled=False)
    with patch("blockchecks.engine.services.metrics.process_rss_bytes", return_value=999 * 1024 * 1024):
        mon.record_pid(1)
    assert mon.recycle_candidates() == []


def test_monitor_rate_limit():
    mon = MemoryMonitor(enabled=True, poll=5.0)
    with patch("blockchecks.engine.services.metrics.time.monotonic", side_effect=[0, 1, 6]):
        assert mon.should_sample() is True  # first check always passes
        assert mon.should_sample() is False  # t=1 within poll
        assert mon.should_sample() is True  # t=6 past poll


def test_worker_over_limit():
    mon = MemoryMonitor(enabled=True, py_max_mib=1)
    with patch("blockchecks.engine.services.metrics.process_rss_bytes", return_value=50 * 1024 * 1024):
        assert mon.worker_over_limit() is True
    mon2 = MemoryMonitor(enabled=True, py_max_mib=99999)
    with patch("blockchecks.engine.services.metrics.process_rss_bytes", return_value=50 * 1024 * 1024):
        assert mon2.worker_over_limit() is False


def test_summary_shape():
    mon = MemoryMonitor(enabled=True, max_mib=100, window=20)
    with patch("blockchecks.engine.services.metrics.process_rss_bytes", return_value=64 * 1024 * 1024):
        mon.record_pid(5)
    s = mon.summary()
    assert s["enabled"] is True
    assert s["windows"] == {"5": 1}
