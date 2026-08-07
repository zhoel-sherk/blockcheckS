"""Unit tests for secure DNS module."""

from unittest.mock import patch

import pytest

from blockchecks.checkers.dns_secure import (
    DnsRunCache,
    _build_dns_query,
    _domain_to_dns_ascii,
    _parse_dns_response,
    audit_domain,
    doh_query,
    has_dns_hijack,
    pick_working_doh,
    prepare_dns_for_run,
    udp_resolve,
)


@pytest.mark.unit
def test_domain_to_dns_ascii_idna():
    assert _domain_to_dns_ascii("пример.рф") == "xn--e1afmkfd.xn--p1ai"
    assert _domain_to_dns_ascii("example.com") == "example.com"


@pytest.mark.unit
def test_build_dns_query_idna_domain():
    wire = _build_dns_query("пример.рф")
    assert b"xn--e1afmkfd" in wire
    assert b"xn--p1ai" in wire


@pytest.mark.unit
def test_udp_resolve_idna_domain():
    with patch("blockchecks.checkers.dns_secure.socket.socket") as mock_sock:
        inst = mock_sock.return_value
        inst.recvfrom.return_value = (b"", ("8.8.8.8", 53))
        ips, err, _ = udp_resolve("пример.рф", "127.0.0.1", timeout=0.1)
    assert ips == []
    sent = inst.sendto.call_args[0][0]
    assert b"xn--e1afmkfd" in sent


@pytest.mark.unit
def test_parse_dns_response_empty_buffer():
    assert _parse_dns_response(b"") == []
    assert _parse_dns_response(b"\x00" * 11) == []


@pytest.mark.unit
def test_parse_dns_response_extracts_a_records():
    """Crafted wire response with one A record → exact IP list."""
    import struct

    # Header: qd=1, an=1
    header = struct.pack("!HHHHHH", 0x4242, 0x8180, 1, 1, 0, 0)
    qname = b"\x07example\x03com\x00"
    question = qname + struct.pack("!HH", 1, 1)  # A IN
    # Answer: pointer to qname at offset 12, type A, class IN, ttl, rdlength=4, 1.2.3.4
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((1, 2, 3, 4))
    assert _parse_dns_response(header + question + answer) == ["1.2.3.4"]


@pytest.mark.unit
def test_udp_resolve_timeout():
    with patch("blockchecks.checkers.dns_secure.socket.socket") as mock_sock:
        inst = mock_sock.return_value
        inst.recvfrom.side_effect = TimeoutError()
        ips, err, _ = udp_resolve("example.com", "127.0.0.1", timeout=0.1)
    assert ips == []
    assert err


@pytest.mark.unit
def test_audit_tampered_when_sets_disjoint():
    with (
        patch("blockchecks.checkers.dns_secure.udp_resolve", return_value=(["8.47.69.6"], "", 1.0)),
        patch("blockchecks.checkers.dns_secure.doh_query", return_value=(["104.18.1.1"], "", 2.0)),
    ):
        r = audit_domain("cloudflare-ech.com", doh_url="https://example/dns-query")
    assert r.tampering_detected
    assert r.verdict == "tampered"
    assert has_dns_hijack([r])


@pytest.mark.unit
def test_audit_ok_when_overlap():
    with (
        patch("blockchecks.checkers.dns_secure.udp_resolve", return_value=(["1.2.3.4"], "", 1.0)),
        patch("blockchecks.checkers.dns_secure.doh_query", return_value=(["1.2.3.4"], "", 2.0)),
    ):
        r = audit_domain("discord.com", doh_url="https://example/dns-query")
    assert not r.tampering_detected
    assert r.verdict == "ok"


@pytest.mark.unit
def test_doh_query_json_then_wire():
    with (
        patch(
            "blockchecks.checkers.dns_secure._doh_json_query",
            return_value=([], "fail", 1.0),
        ),
        patch(
            "blockchecks.checkers.dns_secure._doh_wire_query",
            return_value=(["9.9.9.9"], "", 2.0),
        ),
    ):
        ips, err, _ = doh_query("x.com", "https://doh/")
    assert ips == ["9.9.9.9"]
    assert not err


@pytest.mark.unit
def test_dns_run_cache_ttl():
    cache = DnsRunCache(ttl_sec=3600, doh_server="https://doh/")
    with patch(
        "blockchecks.checkers.dns_secure.doh_query",
        return_value=(["1.1.1.1"], "", 1.0),
    ):
        assert cache.primary_ip("a.com") == "1.1.1.1"
        assert cache.get("a.com") == ["1.1.1.1"]


@pytest.mark.unit
def test_prepare_dns_aborts_on_hijack():
    from blockchecks.checkers.dns_secure import DnsAuditResult

    fake = DnsAuditResult(domain="x.com", tampering_detected=True, verdict="tampered")
    with patch("blockchecks.checkers.dns_secure.audit_domains", return_value=[fake]):
        _, _, rc = prepare_dns_for_run(["x.com"], secure_dns=True)
    assert rc == 1


@pytest.mark.unit
def test_prepare_dns_disabled():
    cache, results, rc = prepare_dns_for_run(["x.com"], secure_dns=False)
    assert cache is None
    assert results == []
    assert rc == 0


@pytest.mark.unit
def test_pick_working_doh_uses_first_success():
    with patch(
        "blockchecks.checkers.dns_secure.doh_query",
        side_effect=[([], "e", 1), (["1.2.3.4"], "", 1)],
    ):
        url = pick_working_doh([("https://a/", "a"), ("https://b/", "b")])
    assert url == "https://b/"
