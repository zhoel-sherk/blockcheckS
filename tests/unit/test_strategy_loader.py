"""Unit tests for StrategyLoader — parse / path / failure modes."""

from __future__ import annotations

from pathlib import Path

import pytest

from blockchecks.engine.strategy_loader import StrategyLoader

pytestmark = pytest.mark.unit


def test_from_string_strips_and_skips_empty():
    assert StrategyLoader.from_string("  fake:repeats=6  ") == ["fake:repeats=6"]
    assert StrategyLoader.from_string("") == []
    assert StrategyLoader.from_string("   ") == []


def test_from_file_skips_comments_and_blanks(tmp_path: Path):
    p = tmp_path / "strats.txt"
    p.write_text(
        "# comment\n\nfake:blob=stun:repeats=6\n  \n# another\nhostfakesplit:nofake2\n",
        encoding="utf-8",
    )
    assert StrategyLoader.from_file(str(p)) == [
        "fake:blob=stun:repeats=6",
        "hostfakesplit:nofake2",
    ]


def test_from_file_expands_literal_backslash_n(tmp_path: Path):
    p = tmp_path / "matrix.txt"
    p.write_text(
        "fake:blob=stun:repeats=6\\nfake:blob=max_ru:repeats=6\n",
        encoding="utf-8",
    )
    assert StrategyLoader.from_file(str(p)) == [
        "fake:blob=stun:repeats=6\nfake:blob=max_ru:repeats=6",
    ]


def test_from_file_empty(tmp_path: Path):
    p = tmp_path / "empty.txt"
    p.write_text("# only comments\n\n", encoding="utf-8")
    assert StrategyLoader.from_file(str(p)) == []


def test_from_config_missing_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError, match="Config not found"):
        StrategyLoader.from_config(str(tmp_path / "nope.conf"))


def test_from_config_and_dir(tmp_path: Path):
    a = tmp_path / "b_alt.conf"
    b = tmp_path / "a_simple.conf"
    a.write_text("--lua-desync=fake\n", encoding="utf-8")
    b.write_text("--lua-desync=hostfakesplit\n", encoding="utf-8")
    (tmp_path / "ignore.txt").write_text("x", encoding="utf-8")

    one = StrategyLoader.from_config(str(b))
    assert one == [str(b.resolve())] or one == [str(b)]

    configs = StrategyLoader.from_config_dir(str(tmp_path))
    assert len(configs) == 2
    assert configs == sorted(configs)
    assert all(c.endswith(".conf") for c in configs)


def test_from_config_warns_empty_or_no_lua_desync(tmp_path: Path, caplog):
    empty = tmp_path / "empty.conf"
    empty.write_text("  \n# only comments\n", encoding="utf-8")
    bare = tmp_path / "bare.conf"
    bare.write_text("--qnum=200\n--filter-tcp=443\n", encoding="utf-8")

    with caplog.at_level("WARNING"):
        assert StrategyLoader.from_config(str(empty)) == [str(empty)]
        assert StrategyLoader.from_config(str(bare)) == [str(bare)]

    assert any("empty" in r.message for r in caplog.records)
    assert any("no --lua-desync" in r.message for r in caplog.records)


def test_from_custom_dir_unknown_protocol(tmp_path: Path):
    with pytest.raises(ValueError, match="Unknown protocol"):
        StrategyLoader.from_custom_dir(str(tmp_path), "nope")


def test_from_custom_dir_missing_file(tmp_path: Path):
    custom = tmp_path / "custom"
    custom.mkdir()
    with pytest.raises(FileNotFoundError, match="Strategy file not found"):
        StrategyLoader.from_custom_dir(str(tmp_path), "tls12")


def test_from_custom_dir_loads(tmp_path: Path):
    custom = tmp_path / "custom"
    custom.mkdir()
    f = custom / "list_https_tls12.txt"
    f.write_text("fake:repeats=6\n# skip\nmultisplit:pos=1\n", encoding="utf-8")
    assert StrategyLoader.from_custom_dir(str(tmp_path), "tls12") == [
        "fake:repeats=6",
        "multisplit:pos=1",
    ]
