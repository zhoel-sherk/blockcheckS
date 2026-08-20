"""TTL / hop-distance helpers."""

from blockchecks.checkers.ttl_probe import (
    autottl_delta,
    hops_from_ttl,
    probe_ttl,
    ttl_reaches_dpi,
)


def test_hops_from_common_initial_ttls():
    assert hops_from_ttl(57) == 7  # 64 - 57
    assert hops_from_ttl(120) == 8  # 128 - 120
    assert hops_from_ttl(250) == 5  # 255 - 250
    assert hops_from_ttl(0) == 0


def test_autottl_delta_needs_dpi_before_origin():
    assert autottl_delta(12, 3) == 3
    assert autottl_delta(3, 3) is None
    assert autottl_delta(12, None) is None


def test_ttl_reaches_dpi_window():
    assert ttl_reaches_dpi(1, dpi_hops=3, server_hops=12) is False
    assert ttl_reaches_dpi(5, dpi_hops=3, server_hops=12) is True
    assert ttl_reaches_dpi(64, dpi_hops=3, server_hops=12) is False
    assert ttl_reaches_dpi(8, dpi_hops=None, server_hops=None) is True


def test_parse_ipv4_tcp_synack_and_rst():
    from blockchecks.checkers.ttl_probe import _parse_ipv4_tcp

    def pkt(ttl: int, tcp_flags: int) -> bytes:
        ip = bytearray(20)
        ip[0] = 0x45
        ip[8] = ttl
        ip[9] = 6
        tcp = bytearray(20)
        tcp[12] = 5 << 4
        tcp[13] = tcp_flags
        return bytes(ip + tcp)

    ttl, flags = _parse_ipv4_tcp(pkt(57, 0x12))
    assert ttl == 57
    assert flags == 0x12  # SYN-ACK
    _, rst = _parse_ipv4_tcp(pkt(54, 0x04))
    assert rst == 0x04
    res = probe_ttl("127.0.0.1", 9, timeout=0.05)
    # No CAP_NET_RAW in unit tests → error recorded, hops stay None
    assert res.server_hops is None or res.error
