"""Checker unit tests — STUN txn-id, smoke imports."""
from __future__ import annotations

import struct
from unittest.mock import MagicMock, patch

import pytest

from checkers.udp_voice import stun_probe
from engine.config import PYTHON_BIN


pytestmark = pytest.mark.unit


def test_python_bin_is_path_string():
    assert isinstance(PYTHON_BIN, str)
    assert PYTHON_BIN  # non-empty
    assert "PYTHON_BIN" != PYTHON_BIN


def test_stun_txn_id_mismatch_rejected():
    tid = b"\x01" * 12
    # Binding success with wrong txn id
    bad = struct.pack(">HHI", 0x0101, 0x0000, 0x2112A442) + (b"\x02" * 12)

    sock = MagicMock()
    sock.recvfrom.return_value = (bad, ("1.2.3.4", 50006))

    with patch("checkers.udp_voice.socket.socket", return_value=sock), \
         patch("checkers.udp_voice.random.randint", return_value=1):
        ok, _, detail = stun_probe("1.2.3.4", 50006, timeout=0.2)
    assert ok is False
    assert "invalid" in detail


def test_stun_txn_id_match_accepted():
    tid = b"\x01" * 12
    good = struct.pack(">HHI", 0x0101, 0x0000, 0x2112A442) + tid

    sock = MagicMock()
    sock.recvfrom.return_value = (good, ("1.2.3.4", 50006))

    with patch("checkers.udp_voice.socket.socket", return_value=sock), \
         patch("checkers.udp_voice.random.randint", return_value=1):
        ok, latency, detail = stun_probe("1.2.3.4", 50006, timeout=0.2)
    assert ok is True
    assert "STUN" in detail
