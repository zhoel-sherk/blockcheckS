"""Unit tests for port block probe (BC2-3)."""

from unittest.mock import patch

import pytest

from blockchecks.checkers.port_block import probe_tcp_port, run_port_block_probe


@pytest.mark.unit
def test_probe_tcp_port_success():
    with patch("blockchecks.checkers.port_block.socket.create_connection"):
        p = probe_tcp_port("1.2.3.4", 443, timeout=1.0)
    assert p.reachable
    assert p.ip == "1.2.3.4"


@pytest.mark.unit
def test_probe_tcp_port_failure():
    with patch(
        "blockchecks.checkers.port_block.socket.create_connection",
        side_effect=OSError("refused"),
    ):
        p = probe_tcp_port("1.2.3.4", 443, timeout=1.0)
    assert not p.reachable
    assert "refused" in p.error


@pytest.mark.unit
def test_run_port_block_probe_multiple_ips():
    from blockchecks.checkers.port_block import PortProbe

    with patch(
        "blockchecks.checkers.port_block.probe_tcp_port",
        side_effect=[
            PortProbe(ip="1.1.1.1", port=443, reachable=True),
            PortProbe(ip="2.2.2.2", port=443, reachable=False, error="x"),
        ],
    ):
        r = run_port_block_probe("example.com", ["1.1.1.1", "2.2.2.2"])
    assert len(r.probes) == 2
    assert r.any_reachable
    assert not r.all_reachable
