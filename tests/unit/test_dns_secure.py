"""Unit tests for secure DNS module."""

from unittest.mock import MagicMock, patch

import pytest

from blockchecks.checkers.dns_secure import (
    CURLOPT_RESOLVE,
    DnsRunCache,
    _build_dns_query,
    _doh_json_query,
    _domain_to_dns_ascii,
    _parse_dns_response,
    audit_domain,
    doh_bootstrap_ip,
    doh_query,
    has_dns_hijack,
    has_dns_sinkhole,
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

    header = struct.pack("!HHHHHH", 0x4242, 0x8180, 1, 1, 0, 0)
    qname = b"\x07example\x03com\x00"
    question = qname + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((1, 2, 3, 4))
    assert _parse_dns_response(header + question + answer) == ["1.2.3.4"]


@pytest.mark.unit
def test_parse_dns_response_mixed_compressed_answer_name():
    """Answer name ``www`` + pointer must not skip an extra byte after the pointer."""
    import struct

    header = struct.pack("!HHHHHH", 0x4242, 0x8180, 1, 1, 0, 0)
    qname = b"\x07example\x03com\x00"
    question = qname + struct.pack("!HH", 1, 1)
    aname = b"\x03www\xc0\x0c"
    answer = aname + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((9, 8, 7, 6))
    assert _parse_dns_response(header + question + answer) == ["9.8.7.6"]


@pytest.mark.unit
def test_parse_dns_response_question_is_pointer():
    """Question name encoded as a compression pointer (no trailing NUL)."""
    import struct

    # header | ptr→18 | QTYPE/QCLASS | labels at 18 | answer RR
    header = struct.pack("!HHHHHH", 0x4242, 0x8180, 1, 1, 0, 0)
    labels = b"\x07example\x03com\x00"
    answer_rr = struct.pack("!HHIH", 1, 1, 60, 4) + bytes((5, 6, 7, 8))
    wire = header + b"\xc0\x12" + struct.pack("!HH", 1, 1) + labels + answer_rr
    assert _parse_dns_response(wire) == ["5.6.7.8"]


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
        patch("blockchecks.checkers.dns_secure.udp_resolve", return_value=(["81.88.1.1"], "", 1.0)),
        patch(
            "blockchecks.checkers.dns_secure.doh_query", return_value=(["93.184.216.34"], "", 2.0)
        ),
    ):
        r = audit_domain("example.com", doh_url="https://example/dns-query")
    assert r.tampering_detected
    assert r.verdict == "tampered"
    assert has_dns_hijack([r])


@pytest.mark.unit
def test_audit_ok_google_googleapis_disjoint_anycast():
    """172.217 vs 173.194 are both Google — not a hijack (LLC Fiord false positive)."""
    with (
        patch(
            "blockchecks.checkers.dns_secure.udp_resolve",
            return_value=(["172.217.20.164"], "", 1.0),
        ),
        patch(
            "blockchecks.checkers.dns_secure.doh_query",
            return_value=(["173.194.220.99", "173.194.220.147"], "", 2.0),
        ),
    ):
        r = audit_domain("googleapis.com", doh_url="https://example/dns-query")
    assert not r.tampering_detected
    assert r.verdict == "ok"
    assert "anycast" in r.description.lower()


@pytest.mark.unit
def test_audit_ok_anycast_cdn_disjoint_ips():
    with (
        patch(
            "blockchecks.checkers.dns_secure.udp_resolve",
            return_value=(["104.16.1.1"], "", 1.0),
        ),
        patch(
            "blockchecks.checkers.dns_secure.doh_query",
            return_value=(["172.64.1.1"], "", 2.0),
        ),
    ):
        r = audit_domain("cloudflare-ech.com", doh_url="https://example/dns-query")
    assert not r.tampering_detected
    assert r.verdict == "ok"
    assert "anycast" in r.description.lower()


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
def test_prepare_dns_warns_on_tampered_does_not_abort():
    from blockchecks.checkers.dns_secure import DnsAuditResult

    fake = DnsAuditResult(domain="x.com", tampering_detected=True, verdict="tampered")
    with (
        patch("blockchecks.checkers.dns_secure.audit_domains", return_value=[fake]),
        patch("blockchecks.checkers.dns_secure.DnsRunCache.prime"),
    ):
        _, _, rc = prepare_dns_for_run(["x.com"], secure_dns=True)
    assert rc == 0
    assert has_dns_hijack([fake])
    assert not has_dns_sinkhole([fake])


@pytest.mark.unit
def test_prepare_dns_aborts_on_sinkhole():
    from blockchecks.checkers.dns_secure import DnsAuditResult

    fake = DnsAuditResult(domain="x.com", tampering_detected=True, verdict="sinkhole")
    with patch("blockchecks.checkers.dns_secure.audit_domains", return_value=[fake]):
        _, _, rc = prepare_dns_for_run(["x.com"], secure_dns=True)
    assert rc == 1
    assert has_dns_sinkhole([fake])


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


@pytest.mark.unit
def test_doh_bootstrap_ip_known_hosts():
    assert doh_bootstrap_ip("https://cloudflare-dns.com/dns-query") == "1.1.1.1"
    assert doh_bootstrap_ip("https://dns.google/dns-query") == "8.8.8.8"
    assert doh_bootstrap_ip("https://dns.quad9.net/dns-query") == "9.9.9.9"
    assert doh_bootstrap_ip("https://unknown.example/dns-query") is None


@pytest.mark.unit
def test_doh_json_setopt_resolve_bootstrap():
    with patch("blockchecks.checkers.dns_secure.curl_cffi.Session") as sess_cls:
        session = sess_cls.return_value.__enter__.return_value
        resp = MagicMock()
        resp.json.return_value = {"Answer": [{"type": 1, "data": "9.9.9.9"}]}
        session.get.return_value = resp
        ips, err, _ = _doh_json_query("example.com", "https://cloudflare-dns.com/dns-query")
    assert ips == ["9.9.9.9"]
    assert not err
    session.curl.setopt.assert_called_once_with(
        CURLOPT_RESOLVE, ["cloudflare-dns.com:443:1.1.1.1"]
    )


@pytest.mark.unit
def test_doh_is_trusted_rejects_yandex():
    from blockchecks.checkers.dns_secure import doh_is_trusted

    assert not doh_is_trusted("https://dns.yandex.ru/dns-query")
    assert doh_is_trusted("https://dns.google/dns-query")


@pytest.mark.unit
def test_pick_working_doh_skips_yandex():
    yandex = "https://dns.yandex.ru/dns-query"
    google = "https://dns.google/dns-query"

    def fake(_domain, url, timeout=5.0):
        return (["1.1.1.1"], "", 1.0) if url == yandex else (["8.8.8.8"], "", 1.0)

    with (
        patch("blockchecks.checkers.dns_secure.DEFAULT_DOH_SERVER", ""),
        patch("blockchecks.checkers.dns_secure.doh_query", side_effect=fake),
    ):
        url = pick_working_doh([(yandex, "Yandex"), (google, "Google")])
    assert url == google


@pytest.mark.unit
def test_audit_yandex_shown_untrusted_not_in_verdict():
    yandex = "https://dns.yandex.ru/dns-query"
    google = "https://dns.google/dns-query"

    def fake(_domain, url, timeout=5.0):
        if "yandex" in url:
            return ["81.88.1.1"], "", 1.0
        return ["1.2.3.4"], "", 1.0

    with (
        patch(
            "blockchecks.checkers.dns_secure.udp_resolve",
            return_value=(["1.2.3.4"], "", 1.0),
        ),
        patch("blockchecks.checkers.dns_secure.doh_query", side_effect=fake),
        patch(
            "blockchecks.checkers.dns_secure.DOH_SERVERS",
            [(google, "Google"), (yandex, "Yandex")],
        ),
        patch("blockchecks.checkers.dns_secure.UNTRUSTED_DOH_URLS", frozenset({yandex})),
    ):
        r = audit_domain("example.com", doh_url=google)
    assert r.verdict == "ok"
    assert not r.tampering_detected
    assert r.doh_ips == ["1.2.3.4"]
    assert r.untrusted_doh.get("Yandex") == ["81.88.1.1"]
    assert r.udp_server == "8.8.8.8"
    assert r.udp_name == "Google"


@pytest.mark.unit
def test_cache_resolve_skips_untrusted_yandex():
    yandex = "https://dns.yandex.ru/dns-query"
    google = "https://dns.google/dns-query"
    cache = DnsRunCache(doh_server="https://dead.example/dns-query")

    def fake(_domain, url, timeout=5.0):
        if url == yandex:
            return ["9.9.9.9"], "", 1.0
        if url == google:
            return ["8.8.8.8"], "", 1.0
        return [], "fail", 1.0

    with (
        patch("blockchecks.checkers.dns_secure.doh_query", side_effect=fake),
        patch(
            "blockchecks.checkers.dns_secure.DOH_SERVERS",
            [(yandex, "Yandex"), (google, "Google")],
        ),
        patch("blockchecks.checkers.dns_secure.UNTRUSTED_DOH_URLS", frozenset({yandex})),
    ):
        ips = cache.resolve("example.com")
    assert ips == ["8.8.8.8"]
    assert cache.doh_server == google


@pytest.mark.unit
def test_doh_display_name_from_catalog():
    from blockchecks.checkers.dns_secure import doh_display_name

    assert doh_display_name("https://cloudflare-dns.com/dns-query") == "Cloudflare"
    assert doh_display_name("https://dns.google/dns-query/") == "Google"
    assert doh_display_name("https://dns.example.net/dns-query") == "dns.example.net"
    assert doh_display_name("") == "DoH"


@pytest.mark.unit
def test_format_audit_table_labels_udp_and_doh():
    from blockchecks.checkers.dns_secure import DnsAuditResult, format_audit_table

    text = format_audit_table(
        [
            DnsAuditResult(
                domain="discord.com",
                udp_ips=["162.159.138.232", "162.159.128.233"],
                doh_ips=["162.159.135.232", "162.159.136.232"],
                doh_server="https://cloudflare-dns.com/dns-query",
                udp_server="8.8.8.8",
                udp_name="Google",
                verdict="ok",
                udp_latency_ms=8.0,
                doh_latency_ms=21.0,
                untrusted_doh={"Yandex": []},
            ),
            DnsAuditResult(
                domain="discordapp.net",
                doh_server="https://cloudflare-dns.com/dns-query",
                udp_server="8.8.8.8",
                udp_name="Google",
                verdict="no_resolution",
                untrusted_doh={"Yandex": []},
            ),
        ]
    )
    assert "plaintext UDP:53" in text
    assert "encrypted DoH" in text
    assert "no DoT" in text
    assert "Google (8.8.8.8)" in text
    assert "Cloudflare" in text
    assert "cloudflare-dns.com" in text
    assert "discord.com" in text
    assert "162.159.138.232" in text
    assert "162.159.135.232" in text
    assert "Yandex=--" not in text
    assert "untrusted — display only" in text
    assert "NO A" in text
    assert "discordapp.net" in text
    assert "Yandex DoH: no answers" in text
    # IPs must not smash into the next cell
    assert "233162.159" not in text


@pytest.mark.unit
def test_format_audit_table_shows_untrusted_only_when_answered():
    from blockchecks.checkers.dns_secure import DnsAuditResult, format_audit_table

    text = format_audit_table(
        [
            DnsAuditResult(
                domain="example.com",
                udp_ips=["1.2.3.4"],
                doh_ips=["1.2.3.4"],
                doh_server="https://dns.google/dns-query",
                udp_server="8.8.8.8",
                udp_name="Google",
                verdict="ok",
                untrusted_doh={"Yandex": ["77.88.8.8"]},
            )
        ]
    )
    assert "77.88.8.8" in text
    assert "untrusted" in text
    assert "Yandex DoH: no answers" not in text
