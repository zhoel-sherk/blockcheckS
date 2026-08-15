"""FailPhase enum + classify_fail_phase taxonomy tests."""

from __future__ import annotations

import pytest

from blockchecks.engine.fail_phase import FailPhase, classify_fail_phase, http_phase


@pytest.mark.unit
def test_fail_phase_stable_values():
    # Every token is a stable string (round-trips through SQLite/JSON).
    assert FailPhase.CONNECT_TIMEOUT.value == "connect_timeout"
    assert FailPhase.DATA_STALL_16K.value == "data_stall_16k"
    assert FailPhase.TLS_RST_AT_SNI.value == "tls_rst_at_sni"
    assert str(FailPhase.DATA_STALL_42K) == "data_stall_42k"


@pytest.mark.unit
def test_phase3_stream_tokens_present():
    for name in (
        "DATA_STALL_TLS_CERT",
        "DATA_STALL_FIRST_REQ",
        "DATA_STALL_7K",
        "DATA_STALL_16K",
        "DATA_STALL_42K",
        "DATA_STALL_64K_PLUS",
        "DELAYED_RST",
        "DELAYED_FIN",
        "TLS_INJECTED_ALERT",
        "ZERO_WINDOW_STALL",
        "H2_RST_STREAM",
    ):
        assert hasattr(FailPhase, name), name


@pytest.mark.unit
def test_http_phase_dynamic_members():
    assert http_phase(403).value == "http_403"
    assert http_phase(451).value == "http_451"
    assert isinstance(http_phase(451), str)
    # cached identity
    assert http_phase(451) is http_phase(451)


@pytest.mark.unit
@pytest.mark.parametrize(
    "error,expected",
    [
        ("curl: (28) Connection timed out", "connect_timeout"),
        ("curl: (35) Recv failure: Connection reset", "tls_rst_at_sni"),
        ("curl: (6) Could not resolve host", "dns_resolve"),
        ("TAMPERED dns mismatch", "dns_tampered"),
        ("sinkhole 198.18.0.1", "dns_sinkhole"),
        ("suspicious redirect 301 to https://x.com", "http_redirect"),
        ("stalled at 7kb", "data_stall_7k"),
        ("stalled at 16kb", "data_stall_16k"),
        ("stalled at 42kb", "data_stall_42k"),
        ("stalled at 64kb reassembly", "data_stall_64k_plus"),
        ("stalled at 2kb cert", "data_stall_tls_cert"),
        ("stalled at first req", "data_stall_first_req"),
        ("zero window advertised", "zero_window_stall"),
        ("HTTP/2 stream reset by RST_STREAM", "h2_rst_stream"),
        ("TLS fatal alert received", "tls_injected_alert"),
        ("fake FIN_ACK injected", "delayed_fin"),
        ("rst after 8kb", "delayed_rst"),
        ("Connection refused", "connect_refused"),
        ("IP block detected 110", "ip_blocked"),
    ],
)
def test_classify_known(error, expected):
    assert classify_fail_phase(error).value == expected


@pytest.mark.unit
def test_classify_empty_and_http():
    assert classify_fail_phase("", 200).value == "pass"
    assert classify_fail_phase("", 403).value == "http_403"
    assert classify_fail_phase("", 0).value == "unknown"
    assert classify_fail_phase("random gibberish").value == "other"
