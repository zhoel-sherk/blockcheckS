"""Unit tests for services.metrics (MemoryMonitor / leak slope)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from blockchecks.service.metrics import (
    MemoryMonitor,
    MemorySample,
    PkillResult,
    _pkill_nfqws2_in_ns,
    compute_leak_slope,
    find_nfqws2_pids,
    pkill_nfqws2_in_ns,
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
    with patch("blockchecks.service.metrics.process_rss_bytes", return_value=0):
        assert process_rss_bytes(999999) == 0


def test_proc_status_value_parses_kb_to_bytes():
    from blockchecks.service.metrics import _proc_status_value

    def _open(path, *args, **kwargs):
        return _TextIO("Name:\tnfqws2\nVmRSS:\t  1234 kB\nVmSize:\t 5678 kB\n")

    with patch("blockchecks.service.metrics.open", side_effect=_open):
        assert _proc_status_value(1, "VmRSS") == 1234 * 1024
        assert _proc_status_value(1, "VmSize") == 5678 * 1024
        assert _proc_status_value(1, "VmPeak") == 0  # field absent


def test_proc_status_value_handles_missing_field():
    from blockchecks.service.metrics import _proc_status_value

    def _open(path, *args, **kwargs):
        return _TextIO("Name:\tnfqws2\n")

    with patch("blockchecks.service.metrics.open", side_effect=_open):
        assert _proc_status_value(1, "VmRSS") == 0


def test_proc_status_value_handles_proc_race():
    from blockchecks.service.metrics import _proc_status_value

    def _open(path, *args, **kwargs):
        raise FileNotFoundError

    with patch("blockchecks.service.metrics.open", side_effect=_open):
        assert _proc_status_value(1, "VmRSS") == 0


def test_find_nfqws2_pids_matches_netns_inode():
    """stdlib path: only nfqws2 whose /proc ns/net inode equals the ns file inode."""

    def _listdir(path):
        if path == "/proc":
            return ["1234", "5678", "9999"]
        raise OSError("unexpected listdir")

    def _readlink(path):
        if "/1234/" in path:
            return "net:[99]"
        if "/5678/" in path:
            return "net:[100]"
        raise FileNotFoundError

    def _open(path, *args, **kwargs):
        if path == "/proc/1234/comm":
            return _TextIO("nfqws2")
        if path == "/proc/5678/comm":
            return _TextIO("nfqws2")
        if path == "/proc/9999/comm":
            return _TextIO("nginx")
        raise FileNotFoundError

    with (
        patch("blockchecks.service.metrics.os.stat") as mock_stat,
        patch("blockchecks.service.metrics.os.listdir", side_effect=_listdir),
        patch("blockchecks.service.metrics.os.readlink", side_effect=_readlink),
        patch("blockchecks.service.metrics.open", side_effect=_open),
    ):
        mock_stat.return_value.st_ino = 99
        assert find_nfqws2_pids("bs-p0") == [1234]


def test_find_nfqws2_pids_missing_ns_file(caplog):
    import logging

    with caplog.at_level(logging.WARNING):
        with patch("blockchecks.service.metrics.os.stat", side_effect=OSError("no such file")):
            assert find_nfqws2_pids("bs-p0") == []
    assert "netns 'bs-p0' missing or unreadable" in caplog.text


def test_find_nfqws2_pids_eperm_uses_sudo_readlink():
    def _listdir(path):
        if path == "/proc":
            return ["1234"]
        raise OSError("unexpected listdir")

    def _readlink(path):
        raise PermissionError("Operation not permitted")

    def _open(path, *args, **kwargs):
        if path == "/proc/1234/comm":
            return _TextIO("nfqws2")
        raise FileNotFoundError

    with (
        patch("blockchecks.service.metrics.os.stat") as mock_stat,
        patch("blockchecks.service.metrics.os.listdir", side_effect=_listdir),
        patch("blockchecks.service.metrics.os.readlink", side_effect=_readlink),
        patch("blockchecks.service.metrics.open", side_effect=_open),
        patch("blockchecks.service.metrics._sudo_readlink", return_value="net:[99]") as sudo_rl,
    ):
        mock_stat.return_value.st_ino = 99
        assert find_nfqws2_pids("bs-p0") == [1234]
    sudo_rl.assert_called_once_with("/proc/1234/ns/net")


def test_find_nfqws2_pids_eperm_sudo_fail_returns_empty():
    def _listdir(path):
        if path == "/proc":
            return ["1234"]
        raise OSError("unexpected listdir")

    def _readlink(path):
        raise PermissionError("Operation not permitted")

    def _open(path, *args, **kwargs):
        if path == "/proc/1234/comm":
            return _TextIO("nfqws2")
        raise FileNotFoundError

    with (
        patch("blockchecks.service.metrics.os.stat") as mock_stat,
        patch("blockchecks.service.metrics.os.listdir", side_effect=_listdir),
        patch("blockchecks.service.metrics.os.readlink", side_effect=_readlink),
        patch("blockchecks.service.metrics.open", side_effect=_open),
        patch("blockchecks.service.metrics._sudo_readlink", return_value=None),
    ):
        mock_stat.return_value.st_ino = 99
        assert find_nfqws2_pids("bs-p0") == []


def test_pkill_nfqws2_in_ns_eperm_retries_sudo(caplog):
    import logging

    with caplog.at_level(logging.WARNING):
        with (
            patch("blockchecks.service.metrics._find_nfqws2_pids", return_value=([4242], 0)),
            patch("blockchecks.service.metrics.os.kill", side_effect=PermissionError("EPERM")),
            patch("blockchecks.service.metrics.subprocess.run") as mock_run,
        ):
            mock_run.return_value.returncode = 0
            assert pkill_nfqws2_in_ns("bs-p0") == 1
    mock_run.assert_called_once_with(
        ["sudo", "-n", "kill", "-9", "4242"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "EPERM killing pid 4242" in caplog.text


def test_pkill_nfqws2_in_ns_sudo_failure_logs_warning(caplog):
    import logging
    from subprocess import CompletedProcess

    with caplog.at_level(logging.WARNING):
        with (
            patch("blockchecks.service.metrics._find_nfqws2_pids", return_value=([4242], 0)),
            patch("blockchecks.service.metrics.os.kill", side_effect=PermissionError("EPERM")),
            patch(
                "blockchecks.service.metrics.subprocess.run",
                return_value=CompletedProcess(
                    args=["sudo", "-n", "kill", "-9", "4242"],
                    returncode=1,
                    stdout="",
                    stderr="not permitted",
                ),
            ),
        ):
            assert pkill_nfqws2_in_ns("bs-p0") == 0
    assert "sudo -n kill -9 4242 failed" in caplog.text


def test_pkill_result_distinguishes_scan_errors():
    with (
        patch("blockchecks.service.metrics._find_nfqws2_pids", return_value=([], 2)),
        patch("blockchecks.service.metrics._kill_pid_sigkill") as mock_kill,
    ):
        result = _pkill_nfqws2_in_ns("bs-p0")
    assert result == PkillResult(killed=0, scan_errors=2)
    mock_kill.assert_not_called()


def test_find_nfqws2_pids_skips_non_nfqws2():
    def _listdir(path):
        if path == "/proc":
            return ["777"]
        raise OSError("unexpected listdir")

    def _readlink(path):
        raise FileNotFoundError

    def _open(path, *args, **kwargs):
        if path == "/proc/777/comm":
            return _TextIO("nginx")
        raise FileNotFoundError

    with (
        patch("blockchecks.service.metrics.os.stat") as mock_stat,
        patch("blockchecks.service.metrics.os.listdir", side_effect=_listdir),
        patch("blockchecks.service.metrics.os.readlink", side_effect=_readlink),
        patch("blockchecks.service.metrics.open", side_effect=_open),
    ):
        mock_stat.return_value.st_ino = 99
        assert find_nfqws2_pids("bs-p0") == []


def test_find_nfqws2_pids_handles_proc_races():
    """Processes that vanish mid-iteration are skipped, not raised."""
    import builtins

    real_open = builtins.open

    def _listdir(path):
        if path == "/proc":
            return ["1111", "2222"]
        raise OSError("unexpected listdir")

    def _readlink(path):
        if "/1111/" in path:
            return "net:[99]"
        raise ProcessLookupError  # 2222 vanished before readlink

    def _open(path, *args, **kwargs):
        if path == "/proc/1111/comm":
            return _TextIO("nfqws2")
        if path == "/proc/2222/comm":
            raise ProcessLookupError  # vanished mid-read
        return real_open(path, *args, **kwargs)

    with (
        patch("blockchecks.service.metrics.os.stat") as mock_stat,
        patch("blockchecks.service.metrics.os.listdir", side_effect=_listdir),
        patch("blockchecks.service.metrics.os.readlink", side_effect=_readlink),
        patch("blockchecks.service.metrics.open", side_effect=_open),
    ):
        mock_stat.return_value.st_ino = 99
        assert find_nfqws2_pids("bs-p0") == [1111]


class _TextIO:
    """Minimal file-like for comm/status mock."""

    def __init__(self, text: str):
        self._lines = text.splitlines(keepends=True)
        self._idx = 0

    def read(self) -> str:
        return "".join(self._lines)

    def __iter__(self):
        return self

    def __next__(self):
        if self._idx >= len(self._lines):
            raise StopIteration
        line = self._lines[self._idx]
        self._idx += 1
        return line

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_monitor_flags_rss_ceiling():
    mon = MemoryMonitor(enabled=True, max_mib=100, window=20)
    with patch("blockchecks.service.metrics.process_rss_bytes", return_value=200 * 1024 * 1024):
        mon.record_pid(42)
        cands = mon.recycle_candidates()
    assert cands == [(42, "rss=200MiB > 100MiB")]


def test_monitor_flags_leak_slope():
    mon = MemoryMonitor(enabled=True, max_mib=1000, leak_slope=8, window=20)
    seq = [100 * 1024 * 1024, 200 * 1024 * 1024, 300 * 1024 * 1024, 400 * 1024 * 1024]
    with patch("blockchecks.service.metrics.time.monotonic", side_effect=[1, 2, 3, 4]):
        with patch("blockchecks.service.metrics.process_rss_bytes", side_effect=seq):
            for _ in seq:
                mon.record_pid(7)
    cands = mon.recycle_candidates()
    assert len(cands) == 1
    assert cands[0][0] == 7
    assert "leak=" in cands[0][1]


def test_monitor_clear_resets_window():
    mon = MemoryMonitor(enabled=True, max_mib=100, window=20)
    with patch("blockchecks.service.metrics.process_rss_bytes", return_value=500 * 1024 * 1024):
        mon.record_pid(9)
        mon.clear(9)
        mon.clear()  # clear-all path
    assert mon.recycle_candidates() == []


def test_monitor_disabled_skips_sampling():
    mon = MemoryMonitor(enabled=False)
    with patch("blockchecks.service.metrics.process_rss_bytes", return_value=999 * 1024 * 1024):
        mon.record_pid(1)
    assert mon.recycle_candidates() == []


def test_monitor_rate_limit():
    mon = MemoryMonitor(enabled=True, poll=5.0)
    with patch("blockchecks.service.metrics.time.monotonic", side_effect=[0, 1, 6]):
        assert mon.should_sample() is True  # first check always passes
        assert mon.should_sample() is False  # t=1 within poll
        assert mon.should_sample() is True  # t=6 past poll


def test_worker_over_limit():
    mon = MemoryMonitor(enabled=True, py_max_mib=1)
    with patch("blockchecks.service.metrics.process_rss_bytes", return_value=50 * 1024 * 1024):
        assert mon.worker_over_limit() is True
    mon2 = MemoryMonitor(enabled=True, py_max_mib=99999)
    with patch("blockchecks.service.metrics.process_rss_bytes", return_value=50 * 1024 * 1024):
        assert mon2.worker_over_limit() is False


def test_summary_shape():
    mon = MemoryMonitor(enabled=True, max_mib=100, window=20)
    with patch("blockchecks.service.metrics.process_rss_bytes", return_value=64 * 1024 * 1024):
        mon.record_pid(5)
    s = mon.summary()
    assert s["enabled"] is True
    assert s["windows"] == {"5": 1}
