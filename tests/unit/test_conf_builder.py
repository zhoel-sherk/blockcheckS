"""Unit tests for conf_builder — nfqws2 config text generation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from blockchecks.engine.conf_builder import (
    _ensure_strategy_n,
    _quote_multiline,
    build_keenetic_conf,
    build_raw_conf,
    write_user_list,
)

pytestmark = pytest.mark.unit


def test_ensure_strategy_n():
    assert _ensure_strategy_n("fake:a", 1) == "fake:a:strategy=1"
    assert _ensure_strategy_n("fake:a:strategy=2", 1) == "fake:a:strategy=2"


def test_quote_multiline():
    assert _quote_multiline("simple") == '"simple"'
    assert _quote_multiline('has "quote"') == '"has \\"quote\\""'
    assert _quote_multiline("simple") == '"simple"'


def test_build_keenetic_conf_structure(tmp_path):
    conf = build_keenetic_conf(
        tcp_strategies=["fake:blob=stun:repeats=6"],
        udp_strategies=["fake:blob=discord_udp:repeats=6"],
        quic_strategies=["fake:blob=quic_initial:repeats=11"],
        isp_interface="eth3",
        prefix=str(tmp_path),
        mode="auto",
        domains=["discord.com", "youtube.com"],
        comment="test",
    )
    assert "ISP_INTERFACE=" in conf
    assert "NFQWS_BASE_ARGS=" in conf
    assert "NFQWS_ARGS=" in conf
    assert "NFQWS_ARGS_QUIC=" in conf
    assert "NFQWS_ARGS_UDP=" in conf
    assert "NFQWS_EXTRA_ARGS=" in conf
    assert "$MODE_AUTO" in conf
    assert "fake:blob=stun:repeats=6:strategy=1" in conf
    assert "# test" in conf
    assert "# domains (2)" in conf


def test_build_keenetic_conf_mode_list():
    conf = build_keenetic_conf(tcp_strategies=["fake:a"], udp_strategies=[], mode="list")
    assert "$MODE_LIST" in conf


def test_build_keenetic_conf_quic_default():
    conf = build_keenetic_conf(tcp_strategies=["fake:a"], udp_strategies=[])
    assert "quic_initial" in conf  # default quic strategy appended


def test_build_keenetic_conf_multiline_strategy():
    multi = "fake:blob=stun:repeats=6\nfake:blob=max_ru:repeats=6"
    conf = build_keenetic_conf(tcp_strategies=[multi], udp_strategies=[])
    assert "fake:blob=stun:repeats=6:strategy=1" in conf
    assert "fake:blob=max_ru:repeats=6:strategy=1" in conf


def test_build_raw_conf_structure(tmp_path):
    conf = build_raw_conf(
        tcp_strategies=["fake:blob=stun:repeats=6"],
        udp_strategies=["fake:blob=discord_udp:repeats=6"],
        quic_strategies=["fake:blob=quic_initial:repeats=11"],
        blobs_dir=str(tmp_path),
        comment="raw test",
        domains=["discord.com"],
    )
    assert "--qnum=200" in conf
    assert "--bind-fix4" in conf
    assert "--hostlist-domains=discord.com" in conf
    assert "--filter-tcp=443" in conf
    assert "--new=quic" in conf
    assert "--new=voice" in conf
    assert "fake:blob=stun:repeats=6:strategy=1" in conf


def test_build_raw_conf_empty_udp():
    conf = build_raw_conf(tcp_strategies=["fake:a"], udp_strategies=[], quic_strategies=[])
    assert "--new=voice" not in conf
    assert "--new=quic" not in conf


def test_build_raw_conf_cli_fragments():
    # quic strategy as raw CLI fragment (starts with --)
    conf = build_raw_conf(
        tcp_strategies=["fake:a"],
        udp_strategies=[],
        quic_strategies=["--filter-udp=443 --fake -1"],
    )
    assert "--filter-udp=443 --fake -1" in conf


def test_write_user_list(tmp_path):
    path = str(tmp_path / "user.list")
    write_user_list(path, ["discord.com", "# comment", "  youtube.com  ", ""])
    lines = Path(path).read_text().splitlines()
    assert lines == ["discord.com", "youtube.com"]


def test_build_keenetic_conf_no_blobs_dir(tmp_path):
    # prefix without blobs → falls back to BLOB_DIR
    with patch("blockchecks.engine.conf_builder.BLOB_DIR", str(tmp_path / "blobs")):
        conf = build_keenetic_conf(tcp_strategies=["fake:a"], udp_strategies=[])
    assert "NFQWS_BASE_ARGS=" in conf
