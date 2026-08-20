"""Tests for netns pool default, ELF arch, and NFQUEUE hygiene."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from blockchecks.engine.config import effective_default_pool_size
from blockchecks.engine.system_deps import _elf_machine, check_nfqws2_arch


@pytest.mark.unit
def test_effective_pool_soft_cap(monkeypatch):
    monkeypatch.setattr(
        "blockchecks.engine.config.DEFAULT_POOL_SIZE",
        4,
    )
    fake = "MemTotal:       900000 kB\nMemAvailable:    400000 kB\n"

    class _F:
        def __enter__(self):
            return iter(fake.splitlines(True))

        def __exit__(self, *a):
            return False

    with patch("builtins.open", return_value=_F()):
        assert effective_default_pool_size() == 1


@pytest.mark.unit
def test_effective_pool_keeps_base_on_xeon(monkeypatch):
    monkeypatch.setattr("blockchecks.engine.config.DEFAULT_POOL_SIZE", 4)
    fake = "MemTotal:       8000000 kB\nMemAvailable:    4000000 kB\n"

    class _F:
        def __enter__(self):
            return iter(fake.splitlines(True))

        def __exit__(self, *a):
            return False

    with patch("builtins.open", return_value=_F()):
        assert effective_default_pool_size() == 4


@pytest.mark.unit
def test_elf_machine_reads_local_python():
    # python binary is ELF on this host
    import sys

    tag = _elf_machine(sys.executable)
    assert tag in {"x86_64", "aarch64", "arm", "x86", None} or (tag and tag.startswith("em_"))


@pytest.mark.unit
def test_check_nfqws2_arch_ok_on_matching(monkeypatch, tmp_path):
    # Craft minimal ELF64 LE x86_64 header
    hdr = bytearray(20)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2  # 64-bit
    hdr[5] = 1  # LE
    hdr[18] = 62  # EM_X86_64
    hdr[19] = 0
    p = tmp_path / "nfq"
    p.write_bytes(bytes(hdr))
    monkeypatch.setattr("blockchecks.engine.system_deps.platform.machine", lambda: "x86_64")
    assert check_nfqws2_arch(str(p)) is None
    monkeypatch.setattr("blockchecks.engine.system_deps.platform.machine", lambda: "armv7l")
    msg = check_nfqws2_arch(str(p))
    assert msg and ("arm" in msg.lower() or "Exec format" in msg)


@pytest.mark.unit
def test_async_uses_nfqueue_constants():
    from blockchecks.engine.async_runner import (
        _build_inline_nfqws_lines,
        _build_quic_nfqws_lines,
    )
    from blockchecks.engine.config import NFQUEUE_TCP, NFQUEUE_UDP

    assert NFQUEUE_TCP != NFQUEUE_UDP
    tcp_lines = _build_inline_nfqws_lines("fake:repeats=1", "tls12")
    assert f"--qnum={NFQUEUE_TCP}" in tcp_lines
    assert f"--qnum={NFQUEUE_UDP}" not in tcp_lines
    quic_lines = _build_quic_nfqws_lines("fake:blob=quic_initial:repeats=1")
    assert f"--qnum={NFQUEUE_UDP}" in quic_lines
    # Footgun: never hardcode queue numbers in source
    src = Path("src/blockchecks/engine/async_runner.py").read_text(encoding="utf-8")
    assert '"--qnum=200"' not in src
    assert "'--qnum=200'" not in src


@pytest.mark.unit
def test_composite_has_queue_bypass():
    src = Path("src/blockchecks/checkers/composite_runner.py").read_text(encoding="utf-8")
    assert "--queue-bypass" in src
    assert "NFQUEUE_TCP" in src
    assert "str(NFQUEUE_UDP)" in src
    lines = src.splitlines()
    for i, line in enumerate(lines):
        if "50000:50100" in line:
            nearby = "\n".join(lines[i : i + 8])
            assert "NFQUEUE_UDP" in nearby
            assert "NFQUEUE_TCP" not in nearby
            break
    else:
        raise AssertionError("multiport 50000:50100 not found")


@pytest.mark.unit
def test_pi2_preset_exists():
    assert Path("presets/domains/pi2.txt").is_file()
