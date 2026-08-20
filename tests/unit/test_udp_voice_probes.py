"""Unit tests for Discord voice UDP probes (RFC5389 + IP Discovery)."""

from unittest.mock import MagicMock, patch

from blockchecks.checkers.udp_voice import (
    IP_DISCOVERY_TOTAL,
    build_ip_discovery_request,
    ip_discovery_probe,
    parse_ip_discovery_response,
    stun_probe,
    voice_udp_probe,
)


def test_build_ip_discovery_request_74_bytes():
    msg = build_ip_discovery_request(0x12345678)
    assert len(msg) == IP_DISCOVERY_TOTAL
    assert msg[:4] == b"\x00\x01\x00\x46"
    assert msg[4:8] == b"\x12\x34\x56\x78"
    assert msg[8:72] == b"\x00" * 64
    assert msg[72:74] == b"\x00\x00"


def test_parse_ip_discovery_response_ok():
    # Type=2, Len=70, SSRC, address "1.2.3.4", port 50001 little-endian
    addr = b"1.2.3.4" + b"\x00" * (64 - 7)
    data = b"\x00\x02\x00\x46" + b"\x00\x00\x00\x01" + addr + b"\x51\xc3"
    parsed = parse_ip_discovery_response(data)
    assert parsed is not None
    assert parsed["mapped_ip"] == "1.2.3.4"
    assert parsed["mapped_port"] == 50001
    assert parsed["raw_len"] == 74


def test_parse_ip_discovery_rejects_wrong_type():
    assert parse_ip_discovery_response(b"\x01\x01" + b"\x00" * 72) is None
    assert parse_ip_discovery_response(b"\x00\x01\x00\x46" + b"\x00" * 70) is None


def test_stun_probe_success():
    tid_holder = {}

    def fake_sendto(msg, addr):
        tid_holder["tid"] = msg[8:20]

    def fake_recvfrom(n):
        tid = tid_holder["tid"]
        # Binding Success 0x0101 + magic + tid
        data = b"\x01\x01\x00\x00\x21\x12\xa4\x42" + tid
        return data, ("35.217.1.1", 50004)

    sock = MagicMock()
    sock.sendto.side_effect = fake_sendto
    sock.recvfrom.side_effect = fake_recvfrom

    with patch("socket.socket", return_value=sock):
        ok, ms, detail = stun_probe("35.217.1.1", 50004, timeout=1.0)

    assert ok is True
    assert "STUN" in detail


def test_ip_discovery_probe_success():
    addr = b"9.9.9.9" + b"\x00" * (64 - 7)
    resp = b"\x00\x02\x00\x46" + b"\x00\x00\x00\x00" + addr + b"\x50\xc3"

    sock = MagicMock()
    sock.recvfrom.return_value = (resp, ("35.217.2.2", 50000))

    with patch("socket.socket", return_value=sock):
        ok, ms, detail = ip_discovery_probe("35.217.2.2", 50000, timeout=1.0)

    assert ok is True
    assert "IP-discovery" in detail
    assert "9.9.9.9" in detail
    sock.sendto.assert_called_once()
    sent = sock.sendto.call_args[0][0]
    assert len(sent) == 74


def test_voice_udp_probe_falls_back_to_ip_discovery():
    with (
        patch(
            "blockchecks.checkers.udp_voice.stun_probe",
            return_value=(False, 1000.0, "timeout"),
        ),
        patch(
            "blockchecks.checkers.udp_voice.ip_discovery_probe",
            return_value=(
                True,
                15.0,
                "74B IP-discovery",
            ),
        ),
    ):
        ok, ms, detail, method = voice_udp_probe("1.1.1.1", 50000, timeout=1.0)

    assert ok is True
    assert method == "ip_discovery"
    assert ms == 15.0


def test_voice_udp_probe_prefers_rfc5389():
    with (
        patch(
            "blockchecks.checkers.udp_voice.stun_probe",
            return_value=(True, 8.0, "20B STUN"),
        ),
        patch(
            "blockchecks.checkers.udp_voice.ip_discovery_probe",
        ) as ipd,
    ):
        ok, ms, detail, method = voice_udp_probe("1.1.1.1", 50000)

    assert ok and method == "rfc5389"
    ipd.assert_not_called()


def test_voice_udp_probe_both_fail():
    with (
        patch(
            "blockchecks.checkers.udp_voice.stun_probe",
            return_value=(False, 1000.0, "timeout"),
        ),
        patch(
            "blockchecks.checkers.udp_voice.ip_discovery_probe",
            return_value=(False, 1000.0, "timeout"),
        ),
    ):
        ok, ms, detail, method = voice_udp_probe("1.1.1.1", 50000)

    assert ok is False
    assert method == ""


def test_voice_burst_probe_success():
    from blockchecks.checkers.udp_voice import voice_burst_probe

    sock = MagicMock()
    sock.recvfrom.return_value = (b"\x80\x78" + b"\x00" * 40, ("35.217.3.3", 50004))

    with patch("socket.socket", return_value=sock):
        ok, ms, detail = voice_burst_probe(
            "35.217.3.3", 50004, timeout=1.0, burst_bytes=17408, packet_size=1400
        )

    assert ok is True
    assert "burst" in detail
    # Total bytes sent must exceed 16KB (17408)
    sent_bytes = sum(len(c[0][0]) for c in sock.sendto.call_args_list)
    assert sent_bytes >= 17408
    assert sent_bytes > 16384


def test_voice_burst_probe_timeout():
    from blockchecks.checkers.udp_voice import voice_burst_probe

    sock = MagicMock()
    sock.recvfrom.side_effect = TimeoutError

    with patch("socket.socket", return_value=sock):
        ok, ms, detail = voice_burst_probe(
            "35.217.3.3", 50004, timeout=1.0, burst_bytes=17408, packet_size=1400
        )

    assert ok is False
    assert "timeout" in detail


def test_voice_burst_probe_unauthenticated_rtp_stun_ok():
    """Discord drops unauthenticated RTP; a later STUN reply means UDP is open."""
    from blockchecks.checkers.udp_voice import voice_burst_probe

    sock = MagicMock()
    sock.recvfrom.side_effect = [
        TimeoutError,
        (b"\x01\x01\x00\x00\x21\x12\xa4\x42" + b"\x00" * 12, ("35.217.3.3", 50004)),
    ]

    with patch("socket.socket", return_value=sock):
        ok, ms, detail = voice_burst_probe(
            "35.217.3.3", 50004, timeout=1.0, burst_bytes=17408, packet_size=1400
        )

    assert ok is True
    assert "unauthenticated RTP" in detail
    assert "STUN" in detail


def test_voice_udp_probe_try_burst_on_fail():

    with (
        patch(
            "blockchecks.checkers.udp_voice.stun_probe",
            return_value=(False, 1000.0, "timeout"),
        ),
        patch(
            "blockchecks.checkers.udp_voice.ip_discovery_probe",
            return_value=(False, 1000.0, "timeout"),
        ),
        patch(
            "blockchecks.checkers.udp_voice.voice_burst_probe",
            return_value=(True, 25.0, "X B UDP reply to 17408B burst"),
        ),
    ):
        ok, ms, detail, method = voice_udp_probe("1.1.1.1", 50000, try_burst=True)

    assert ok is True
    assert method == "burst"
    assert ms == 25.0


def test_voice_udp_probe_no_burst_by_default():
    with (
        patch(
            "blockchecks.checkers.udp_voice.stun_probe",
            return_value=(False, 1000.0, "timeout"),
        ),
        patch(
            "blockchecks.checkers.udp_voice.ip_discovery_probe",
            return_value=(False, 1000.0, "timeout"),
        ),
        patch(
            "blockchecks.checkers.udp_voice.voice_burst_probe",
        ) as burst,
    ):
        ok, ms, detail, method = voice_udp_probe("1.1.1.1", 50000)

    assert ok is False
    burst.assert_not_called()
