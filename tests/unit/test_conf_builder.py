"""Unit tests for conf_builder — nfqws2 config text generation."""

from __future__ import annotations

from pathlib import Path

import pytest

from blockchecks.engine.conf_builder import (
    _ensure_strategy_n,
    _quote_multiline,
    build_keenetic_conf,
    build_raw_conf,
    write_export_bundle,
    write_user_list,
)

pytestmark = pytest.mark.unit


def _working(conf: str) -> str:
    return "\n".join(
        ln for ln in conf.splitlines() if ln.strip() and not ln.lstrip().startswith("#")
    )


def _desync_values(conf: str) -> list[str]:
    return [
        part.split("--lua-desync=", 1)[1]
        for ln in _working(conf).splitlines()
        for part in ln.split()
        if part.startswith("--lua-desync=")
    ]


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


def test_build_keenetic_conf_no_blobs_dir():
    """Missing host {prefix}/blobs must not leak BLOB_DIR into working lines."""
    from blockchecks.engine.config import BLOB_DIR

    conf = build_keenetic_conf(tcp_strategies=["fake:blob=stun"], udp_strategies=[])
    working = _working(conf)
    assert "--blob=stun:@/opt/etc/nfqws2/blobs/stun.bin" in working
    assert BLOB_DIR not in working
    assert "/opt/zapret2/lua/" not in working
    assert "--lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua" in working


def test_custom_lua_comment_dupfake():
    from blockchecks.engine.conf_builder import custom_lua_copy_comments

    comments = custom_lua_copy_comments("dupfake:blob=tls_clienthello:repeats=6:tcp_ts=-1000")
    assert comments
    hint = comments[0]
    assert hint.startswith("# COPY lua:")
    assert "lua/custom/dupfake.lua" in hint
    assert "-> /opt/etc/nfqws2/lua/dupfake.lua" in hint


def test_custom_lua_comment_unknown_function_defaults():
    from blockchecks.engine.conf_builder import custom_lua_copy_comments

    assert custom_lua_copy_comments("mystery_core:pos=1") == []


def test_custom_lua_comment_stock_no_hint():
    from blockchecks.engine.conf_builder import custom_lua_copy_comments

    for strat in (
        "fake:blob=stun:repeats=6",
        "hostfakesplit:nofake2:tcp_ts=-1000:repeats=1",
        "multisplit:pos=1:seqovl=568",
    ):
        assert custom_lua_copy_comments(strat) == []


def test_build_raw_conf_includes_custom_lua_hint():
    conf = build_raw_conf(
        tcp_strategies=["dupfake:blob=tls_clienthello:repeats=6:tcp_ts=-1000"],
        udp_strategies=[],
    )
    assert "lua/custom/dupfake.lua" in conf
    assert "# COPY lua:" in conf
    assert "--lua-init=" in conf and "dupfake.lua" in conf


def test_build_keenetic_conf_includes_custom_lua_hint():
    conf = build_keenetic_conf(
        tcp_strategies=["dupfake:blob=stun+max_ru:repeats=6:tcp_ts=-1000"],
        udp_strategies=[],
    )
    assert "lua/custom/dupfake.lua" in conf
    assert "# COPY lua:" in conf
    assert "--lua-init=@/opt/etc/nfqws2/lua/dupfake.lua" in conf


def test_build_raw_conf_no_hint_for_stock():
    conf = build_raw_conf(
        tcp_strategies=["fake:blob=stun:repeats=6"],
        udp_strategies=[],
    )
    assert "COPY lua:" not in conf


def test_load_custom_lua_manifest_has_dupfake():
    from blockchecks.engine.conf_builder import load_custom_lua_manifest

    m = load_custom_lua_manifest()
    assert "dupfake" in m
    assert m["dupfake"]["file"] == "dupfake.lua"
    assert "blob" in m["dupfake"]["included"]
    assert "pos" in m["dupfake"]["excluded"]


def test_validate_custom_lua_params_excluded():
    from blockchecks.engine.conf_builder import validate_custom_lua_params

    issues = validate_custom_lua_params("dupfake:blob=stun:repeats=6:pos=1")
    assert any("excluded" in i and "pos" in i for i in issues)


def test_validate_custom_lua_params_undocumented():
    from blockchecks.engine.conf_builder import validate_custom_lua_params

    issues = validate_custom_lua_params("dupfake:blob=stun:repeats=6:mystery=1")
    assert any("undocumented" in i and "mystery" in i for i in issues)


def test_validate_custom_lua_params_ok():
    from blockchecks.engine.conf_builder import validate_custom_lua_params

    assert validate_custom_lua_params("dupfake:blob=stun:repeats=6:tcp_ts=-1000") == []
    assert validate_custom_lua_params("fake:blob=stun:repeats=6") == []


def test_validate_custom_lua_params_optional_allowed():
    from blockchecks.engine.conf_builder import validate_custom_lua_params

    assert validate_custom_lua_params("dupfake:blob=stun:repeats=6:optional") == []


def test_build_raw_conf_ipset_ips_inline():
    conf = build_raw_conf(
        tcp_strategies=["fake:blob=stun"], udp_strategies=[], ipset_ips=["1.2.3.4", "5.6.7.8"]
    )
    assert "--ipset-ip=1.2.3.4,5.6.7.8" in conf


def test_build_raw_conf_ipset_file():
    conf = build_raw_conf(
        tcp_strategies=["fake:blob=stun"], udp_strategies=[], ipset_file="/tmp/u.ipset"
    )
    assert "--ipset=@/tmp/u.ipset" in conf


def test_build_raw_conf_ipset_file_wins_over_ips():
    conf = build_raw_conf(
        tcp_strategies=["fake:blob=stun"],
        udp_strategies=[],
        ipset_ips=["1.2.3.4"],
        ipset_file="/tmp/u.ipset",
    )
    assert "--ipset=@/tmp/u.ipset" in conf
    assert "--ipset-ip" not in conf


def test_build_raw_conf_no_ipset_by_default():
    conf = build_raw_conf(tcp_strategies=["fake:blob=stun"], udp_strategies=[])
    assert "--ipset" not in conf


def test_build_keenetic_conf_ipset_ips():
    conf = build_keenetic_conf(
        tcp_strategies=["fake:blob=stun"], udp_strategies=[], ipset_ips=["1.2.3.4"]
    )
    assert "--ipset-ip=1.2.3.4" in conf


def test_build_keenetic_conf_ipset_file():
    conf = build_keenetic_conf(
        tcp_strategies=["fake:blob=stun"], udp_strategies=[], ipset_file="/etc/bs/user.ipset"
    )
    assert "--ipset=@/opt/etc/nfqws2/lists/user.ipset" in _working(conf)
    assert "# COPY ipset: /etc/bs/user.ipset -> /opt/etc/nfqws2/lists/user.ipset" in conf
    assert "--ipset=@/etc/bs/user.ipset" not in _working(conf)


def test_keenetic_working_lines_have_no_host_abs():
    from blockchecks.engine.config import BLOB_DIR, PROJECT_DIR

    conf = build_keenetic_conf(
        tcp_strategies=["fake:blob=stun:repeats=6:tcp_ts=-1000"],
        udp_strategies=["fake:blob=discord_udp:repeats=6"],
    )
    working = _working(conf)
    assert "/home/" not in working
    assert "workspace/blockcheckS" not in working
    assert BLOB_DIR not in working
    assert PROJECT_DIR not in working
    assert "/opt/zapret2/" not in working
    for val in _desync_values(conf):
        assert "/" not in val
        assert ".conf" not in val
    assert "--blob=stun:@/opt/etc/nfqws2/blobs/stun.bin" in working
    assert "49152-65535" in working
    assert "49152:65535" in conf


def test_keenetic_config_path_extracts_function_cores():
    from blockchecks.engine.config import CONFIGS_DIR

    conf_path = str(Path(CONFIGS_DIR) / "simple_fake_alt2__fake_max_ru_ts.conf")
    conf = build_keenetic_conf(tcp_strategies=[str(conf_path)], udp_strategies=[])
    working = _working(conf)
    assert str(conf_path) not in working
    assert "fake:blob=stun:repeats=6:tcp_ts=-1000:strategy=1" in working
    assert "fake:blob=max_ru:repeats=6:tcp_ts=-1000:strategy=1" in working
    for val in _desync_values(conf):
        assert not val.startswith("/")
        assert ".conf" not in val


def test_keenetic_skips_unreadable_conf_path(tmp_path):
    missing = tmp_path / "nope.conf"
    conf = build_keenetic_conf(tcp_strategies=[str(missing)], udp_strategies=[])
    assert str(missing) not in _working(conf)
    assert "--lua-desync=" in conf  # circular / http_methodeol remain


def test_keenetic_strips_host_paths_from_cli_fragment():
    frag = (
        "--filter-udp=443 --blob=QUIC:@/home/zhoel/workspace/blockcheckS/blobs/x.bin "
        "--payload=quic_initial --lua-desync=fake:blob=QUIC:repeats=2"
    )
    conf = build_keenetic_conf(tcp_strategies=[frag], udp_strategies=[])
    assert "/home/" not in _working(conf)
    assert "fake:blob=QUIC:repeats=2:strategy=1" in conf
    assert "--blob=QUIC:@/home" not in _working(conf)


def test_write_export_bundle_copies_custom_blob_and_lua(tmp_path):
    tcp = ["dupfake:blob=stun:repeats=6:tcp_ts=-1000"]
    text = build_keenetic_conf(tcp_strategies=tcp, udp_strategies=[])
    out = write_export_bundle(text, tmp_path, tcp_strats=tcp, conf_name="nfqws2.conf")
    assert out.is_file()
    assert (tmp_path / "blobs" / "stun.bin").is_file()
    assert (tmp_path / "lua" / "dupfake.lua").is_file()
    assert not (tmp_path / "blobs" / "quic_initial.bin").exists()


def test_keenetic_empty_udp_omits_circular_and_discord_blob():
    conf = build_keenetic_conf(tcp_strategies=["fake:blob=stun"], udp_strategies=[])
    udp = conf.split("NFQWS_ARGS_UDP=", 1)[1].split("NFQWS_EXTRA_ARGS", 1)[0]
    assert "circular" not in udp
    assert "discord_udp" not in _working(conf)
    assert "--blob=stun:@" in _working(conf)


def test_keenetic_skips_ip_ttl_outside_byte():
    conf = build_keenetic_conf(
        tcp_strategies=[
            "fake:blob=stun:repeats=6:ip_ttl=512",
            "fake:blob=max_ru:repeats=2",
        ],
        udp_strategies=[],
    )
    assert "ip_ttl=512" not in conf
    assert "blob=max_ru" in conf
    assert "circular:" in conf.split("NFQWS_ARGS=", 1)[1].split("NFQWS_ARGS_QUIC", 1)[0]


def test_keenetic_skips_digit_blob_alias():
    conf = build_keenetic_conf(
        tcp_strategies=["fake:blob=4pda:repeats=2", "fake:blob=stun:repeats=6"],
        udp_strategies=[],
    )
    assert "blob=4pda" not in _working(conf)
    assert "blob=stun" in _working(conf)


def test_raw_blobs_only_from_cores():
    conf = build_raw_conf(tcp_strategies=["fake:blob=stun"], udp_strategies=[])
    working = _working(conf)
    assert "--blob=stun:" in working
    assert "discord_udp" not in working
    assert "max_ru" not in working
    assert "(" not in "\n".join(ln for ln in conf.splitlines() if ln.lstrip().startswith("#"))
