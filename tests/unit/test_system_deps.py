"""Unit tests for system_deps (no network)."""

from __future__ import annotations

import pytest

from blockchecks.engine import system_deps as sd

pytestmark = pytest.mark.unit


def test_zapret2_arch_mapping():
    assert sd.zapret2_arch("x86_64") == "linux-x86_64"
    assert sd.zapret2_arch("AMD64") == "linux-x86_64"
    assert sd.zapret2_arch("aarch64") == "linux-arm64"
    assert sd.zapret2_arch("arm64") == "linux-arm64"
    assert sd.zapret2_arch("obscure-cpu") is None


def test_parse_sha256sum():
    d1 = "a" * 64
    d2 = "b" * 64
    text = f"{d1}  zapret2-v1.0.4.tar.gz\n{d2} *other.bin\n"
    m = sd.parse_sha256sum(text)
    assert m["zapret2-v1.0.4.tar.gz"] == d1
    assert m["other.bin"] == d2


def test_sha256_file(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"hello")
    assert sd.sha256_file(p) == ("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")


def test_resolve_nfqws2_order(tmp_path, monkeypatch):
    fake = tmp_path / "nfqws2"
    fake.write_text("x")
    fake.chmod(0o755)
    monkeypatch.setenv("BLOCKCHECKS_NFQWS2", str(fake))
    monkeypatch.setattr(sd.shutil, "which", lambda _: None)
    assert sd.resolve_nfqws2_bin() == str(fake)


def test_verify_missing_nofetch(monkeypatch):
    monkeypatch.setattr(sd, "resolve_nfqws2_bin", lambda: None)
    report = sd.verify_system_dependencies(fetch=False, offline=True, require_linux=False)
    assert report.ok is False
    assert any("nfqws2 not found" in e for e in report.errors)


def test_apply_tool_paths_refresh(tmp_path):
    from blockchecks.engine import config as cfg

    nfq = tmp_path / "nfqws2"
    nfq.write_text("x")
    lua = tmp_path / "lua"
    lua.mkdir()
    (lua / "zapret-lib.lua").write_text("--")
    blobs = tmp_path / "blobs"
    blobs.mkdir()

    cfg.apply_tool_paths(nfqws2=str(nfq), blobs=str(blobs), lua_dir=str(lua))
    assert cfg.get_nfqws2_bin() == str(nfq)
    assert str(blobs) == cfg.BLOB_DIR
    assert str(lua) == cfg.LUA_INIT_DIR
    assert any("zapret-lib.lua" in p for p in cfg.get_lua_init_scripts())
