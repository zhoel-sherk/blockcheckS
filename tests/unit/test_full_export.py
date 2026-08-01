"""Unit tests for conf_builder + DB best/coverage + nfconf."""

from pathlib import Path

import pytest

from blockchecks.engine.conf_builder import (
    build_keenetic_conf,
    build_raw_conf,
    extract_blob_names,
)
from blockchecks.engine.db_logger import StateDB
from blockchecks.nfconf import export_configs


def test_extract_blob_names():
    names = extract_blob_names(
        "fake:blob=stun:repeats=6",
        "fake:blob=discord_udp:repeats=3",
        "multisplit:seqovl_pattern=tls_clienthello",
    )
    assert "stun" in names
    assert "discord_udp" in names
    assert "tls_clienthello" in names


def test_build_keenetic_has_required_keys():
    text = build_keenetic_conf(
        tcp_strategies=["fake:blob=stun:repeats=6:tcp_ts=-1000"],
        udp_strategies=["fake:blob=discord_udp:repeats=6"],
        isp_interface="eth3",
        domains=["discord.com", "youtube.com"],
    )
    assert 'ISP_INTERFACE="eth3"' in text or "ISP_INTERFACE=" in text
    assert "NFQWS_BASE_ARGS=" in text
    assert "NFQWS_ARGS=" in text
    assert "NFQWS_ARGS_QUIC=" in text
    assert "NFQWS_ARGS_UDP=" in text
    assert "NFQWS_EXTRA_ARGS=" in text
    assert "UDP_PORTS=" in text
    assert "strategy=1" in text
    assert "fake:blob=stun" in text
    assert "discord_udp" in text


def test_build_raw_has_no_isp():
    text = build_raw_conf(
        tcp_strategies=["fake:blob=max_ru:repeats=6"],
        udp_strategies=["fake:blob=discord_udp:repeats=6"],
        domains=["discord.com"],
    )
    assert "ISP_INTERFACE" not in text
    assert "MODE_AUTO" not in text
    assert "--lua-desync=" in text
    assert "--new=voice" in text
    assert "strategy=1" in text


@pytest.mark.asyncio
async def test_db_best_and_coverage(tmp_path):
    db = StateDB(str(tmp_path / "t.db"))
    await db.init()
    await db.log_tcp(
        "s1",
        "discord.com",
        "PASS",
        100.0,
        200,
        config_path="fake:blob=stun:repeats=6",
    )
    await db.log_tcp(
        "s1",
        "youtube.com",
        "PASS",
        120.0,
        200,
        config_path="fake:blob=stun:repeats=6",
    )
    await db.log_tcp(
        "s2",
        "discord.com",
        "PASS",
        50.0,
        200,
        config_path="fake:blob=max_ru:repeats=6",
    )
    await db.log_tcp("s3", "discord.com", "FAIL", 0.0, 0)

    assert await db.has_tcp_result("s1", "discord.com")
    assert not await db.has_tcp_result("missing", "discord.com")

    best = await db.get_best_tcp("discord.com", limit=5)
    assert best[0]["strategy"] == "s2"  # lower latency
    assert len(best) == 2

    cov = await db.coverage_score("s1")
    assert cov["domains_passed"] == 2

    ranked = await db.get_best_by_coverage(limit=5)
    assert ranked[0]["strategy"] == "s1"
    assert ranked[0]["domains_passed"] == 2

    common = await db.get_common_tcp(["discord.com", "youtube.com"], limit=5)
    assert [c["strategy"] for c in common] == ["s1"]
    assert common[0]["domains_passed"] == 2

    cfg = await db.get_strategy_config("s1", "tcp")
    assert "stun" in cfg


@pytest.mark.asyncio
async def test_export_common_intersection(tmp_path):
    db_path = str(tmp_path / "state.db")
    db = StateDB(db_path)
    await db.init()
    await db.log_tcp(
        "common",
        "discord.com",
        "PASS",
        90.0,
        200,
        config_path="fake:blob=stun:repeats=6",
    )
    await db.log_tcp(
        "common",
        "youtube.com",
        "PASS",
        95.0,
        200,
        config_path="fake:blob=stun:repeats=6",
    )
    await db.log_tcp(
        "discord_only",
        "discord.com",
        "PASS",
        50.0,
        200,
        config_path="fake:blob=max_ru:repeats=6",
    )

    domains = tmp_path / "domains.txt"
    domains.write_text("discord.com\nyoutube.com\n", encoding="utf-8")
    out = tmp_path / "output"

    result = await export_configs(
        db_path=db_path,
        domain="discord.com",
        limit=3,
        out_dir=str(out),
        domains_file=str(domains),
        timestamp="common",
        common_only=True,
    )
    assert len(result["tcp"]) == 1
    assert "stun" in result["tcp"][0]


@pytest.mark.asyncio
async def test_export_configs_writes_files(tmp_path):
    db_path = str(tmp_path / "state.db")
    db = StateDB(db_path)
    await db.init()
    await db.log_tcp(
        "lab1",
        "discord.com",
        "PASS",
        80.0,
        200,
        config_path="fake:blob=stun:repeats=6:tcp_ts=-1000",
    )
    await db.log_udp(
        "u1",
        "35.1.1.1:50000",
        "PASS",
        30.0,
        config_path="fake:blob=discord_udp:repeats=6",
    )
    await db.log_pair(
        "lab1",
        "u1",
        "discord.com",
        True,
        True,
        True,
        80.0,
        0.0,
        30.0,
        "PASS",
    )

    out = tmp_path / "output"
    domains = tmp_path / "domains.txt"
    domains.write_text("discord.com\nyoutube.com\n", encoding="utf-8")

    result = await export_configs(
        db_path=db_path,
        domain="discord.com",
        limit=2,
        out_dir=str(out),
        domains_file=str(domains),
        timestamp="testrun",
    )
    assert Path(result["keenetic"]).exists()
    assert Path(result["raw"]).exists()
    assert Path(result["user_list"]).exists()
    keen = Path(result["keenetic"]).read_text(encoding="utf-8")
    raw = Path(result["raw"]).read_text(encoding="utf-8")
    assert "ISP_INTERFACE" in keen
    assert "ISP_INTERFACE" not in raw
    assert "stun" in keen
    assert "discord_udp" in keen
    user = Path(result["user_list"]).read_text(encoding="utf-8")
    assert "discord.com" in user
