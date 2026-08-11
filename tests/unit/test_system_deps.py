"""Unit tests for system_deps (no network)."""

from __future__ import annotations

import os

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


# ── ELF arch detection ────────────────────────────────────────────────


def test_elf_machine_x86_64(tmp_path):
    p = tmp_path / "bin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 14 + b"\x3e\x00")  # em=62 little-endian
    assert sd._elf_machine(str(p)) == "x86_64"


def test_elf_machine_not_elf(tmp_path):
    p = tmp_path / "bin"
    p.write_text("not elf")
    assert sd._elf_machine(str(p)) is None


def test_elf_machine_missing_file(tmp_path):
    assert sd._elf_machine(str(tmp_path / "nope")) is None


def test_host_elf_expected(monkeypatch):
    monkeypatch.setattr(sd.platform, "machine", lambda: "x86_64")
    assert sd._host_elf_expected() == "x86_64"
    monkeypatch.setattr(sd.platform, "machine", lambda: "aarch64")
    assert sd._host_elf_expected() == "aarch64"


def test_check_nfqws2_arch_match(tmp_path, monkeypatch):
    p = tmp_path / "bin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 14 + b"\x3e\x00")
    monkeypatch.setattr(sd.platform, "machine", lambda: "x86_64")
    assert sd.check_nfqws2_arch(str(p)) is None


def test_check_nfqws2_arch_mismatch(tmp_path, monkeypatch):
    p = tmp_path / "bin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 14 + b"\xb7\x00")  # em=183 aarch64
    monkeypatch.setattr(sd.platform, "machine", lambda: "x86_64")
    warn = sd.check_nfqws2_arch(str(p))
    assert warn is not None
    assert "Exec format error" in warn


# ── DepsReport.print_report / fetch_deps_enabled ──────────────────────


def test_fetch_deps_enabled(monkeypatch):
    monkeypatch.delenv("BLOCKCHECKS_FETCH_DEPS", raising=False)
    assert sd.fetch_deps_enabled(True) is True
    monkeypatch.setenv("BLOCKCHECKS_FETCH_DEPS", "0")
    assert sd.fetch_deps_enabled(True) is False
    monkeypatch.setenv("BLOCKCHECKS_FETCH_DEPS", "true")
    assert sd.fetch_deps_enabled(False) is True


def test_deps_report_print(capsys):
    report = sd.DepsReport(ok=True, nfqws2="/x/nfqws2", warnings=["w1"])
    report.print_report()
    out = capsys.readouterr().out
    assert "OK" in out and "w1" in out


# ── resolve_nfqws2_bin ────────────────────────────────────────────────


def test_resolve_nfqws2_env(monkeypatch, tmp_path):
    bin = tmp_path / "nfqws2"
    bin.write_text("x")
    bin.chmod(0o755)
    monkeypatch.setenv("BLOCKCHECKS_NFQWS2", str(bin))
    assert sd.resolve_nfqws2_bin() == str(bin)


def test_resolve_nfqws2_which(monkeypatch):
    import shutil
    from pathlib import Path

    monkeypatch.delenv("BLOCKCHECKS_NFQWS2", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/nfqws2")
    monkeypatch.setattr(sd, "VENDOR_BIN_LINK", Path("/nonexistent/bin/nfqws2"))
    monkeypatch.setattr(sd, "VENDOR_ROOT", Path("/nonexistent"))
    real = os.path.isfile
    monkeypatch.setattr(sd.os.path, "isfile", lambda p: p == "/usr/bin/nfqws2" or real(p))
    assert sd.resolve_nfqws2_bin() == "/usr/bin/nfqws2"


def test_resolve_nfqws2_none(monkeypatch):
    import shutil
    from pathlib import Path

    monkeypatch.delenv("BLOCKCHECKS_NFQWS2", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(sd, "VENDOR_BIN_LINK", Path("/nonexistent/bin/nfqws2"))
    monkeypatch.setattr(sd, "VENDOR_ROOT", Path("/nonexistent"))
    monkeypatch.setattr(sd, "zapret2_arch", lambda: None)
    monkeypatch.setattr(sd.os.path, "isfile", lambda p: False)
    assert sd.resolve_nfqws2_bin() is None


# ── verify_system_dependencies ────────────────────────────────────────


def test_verify_non_linux(monkeypatch):
    monkeypatch.setattr(sd.sys, "platform", "win32")
    report = sd.verify_system_dependencies(require_linux=True)
    assert report.ok is False
    assert "Linux" in report.errors[0]


def test_verify_nfqws2_found(monkeypatch, tmp_path):
    bin = tmp_path / "nfqws2"
    bin.write_text("x")
    bin.chmod(0o755)
    monkeypatch.setattr(sd, "sys", __import__("sys"))
    monkeypatch.setattr(sd.sys, "platform", "linux")
    monkeypatch.setattr(sd.shutil, "which", lambda name: None)
    monkeypatch.setattr(sd, "resolve_nfqws2_bin", lambda: str(bin))
    report = sd.verify_system_dependencies(fetch=False)
    assert report.ok is True
    assert report.nfqws2 == str(bin)


def test_verify_fetch_failure(monkeypatch):
    monkeypatch.setattr(sd, "sys", __import__("sys"))
    monkeypatch.setattr(sd.sys, "platform", "linux")
    monkeypatch.setattr(sd.shutil, "which", lambda name: None)
    monkeypatch.setattr(sd, "resolve_nfqws2_bin", lambda: None)

    def _boom(**kw):
        raise RuntimeError("network down")

    monkeypatch.setattr(sd, "ensure_zapret2_vendor", _boom)
    report = sd.verify_system_dependencies(fetch=True, offline=False)
    assert report.ok is False
    assert any("auto-fetch failed" in e for e in report.errors)


# ── _seed_blobs_from_fake / ensure_zapret2_vendor ─────────────────────


def test_seed_blobs_from_fake(tmp_path):
    from blockchecks.engine.system_deps import _seed_blobs_from_fake

    fake = tmp_path / "fake"
    fake.mkdir()
    (fake / "stun.bin").write_bytes(b"stun")
    (fake / "custom.bin").write_bytes(b"custom")
    blobs = tmp_path / "blobs"
    blobs.mkdir()
    n = _seed_blobs_from_fake(fake, blobs)
    assert n >= 1
    assert (blobs / "stun.bin").exists()


def test_seed_blobs_from_fake_no_dir(tmp_path):
    from blockchecks.engine.system_deps import _seed_blobs_from_fake

    assert _seed_blobs_from_fake(tmp_path / "nope", tmp_path / "blobs") == 0


def test_ensure_zapret2_vendor_offline():
    from blockchecks.engine.system_deps import ensure_zapret2_vendor

    with pytest.raises(RuntimeError, match="offline"):
        ensure_zapret2_vendor(offline=True)


def test_ensure_zapret2_vendor_bad_arch(monkeypatch):
    from blockchecks.engine.system_deps import ensure_zapret2_vendor

    monkeypatch.setattr("blockchecks.engine.system_deps.zapret2_arch",
                        lambda: None)
    monkeypatch.setattr("blockchecks.engine.system_deps.platform.machine",
                        lambda: "weird-arch")
    with pytest.raises(RuntimeError, match="unsupported CPU arch"):
        ensure_zapret2_vendor(offline=False)
