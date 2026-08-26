"""Unit tests for secure_io — restrictive file writing helpers."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from blockchecks.engine.secure_io import write_secure_text

pytestmark = pytest.mark.unit


def test_write_secure_text_creates(tmp_path):
    path = str(tmp_path / "sub" / "token.txt")
    write_secure_text(path, "secret")
    assert Path(path).read_text() == "secret"
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_write_secure_text_overwrites(tmp_path):
    path = tmp_path / "f.txt"
    write_secure_text(str(path), "first")
    write_secure_text(str(path), "second")
    assert Path(path).read_text() == "second"


def test_write_secure_text_cleanup_on_failure(tmp_path):
    path = tmp_path / "f.txt"
    # content that raises (non-encodable) → tmp removed, no partial file
    with pytest.raises(UnicodeEncodeError):
        write_secure_text(str(path), "\ud800")
    assert not path.exists()
    leftovers = list(tmp_path.glob("*.tmp.*"))
    assert leftovers == []


def test_write_secure_text_reclaims_sudo_ownership(tmp_path, monkeypatch):
    called: list[str] = []

    def fake_reclaim(path):
        called.append(str(path))

    monkeypatch.setattr("blockchecks.engine.secure_io.reclaim_sudo_ownership", fake_reclaim)
    path = tmp_path / "token.txt"
    write_secure_text(str(path), "secret")
    assert called == [str(path)]


def test_write_secure_text_logs_oserror(tmp_path, monkeypatch, caplog):
    path = tmp_path / "f.txt"

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("blockchecks.engine.secure_io.os.replace", boom)
    with caplog.at_level("WARNING"):
        with pytest.raises(OSError, match="disk full"):
            write_secure_text(str(path), "x")
    assert any("secure write failed" in r.message for r in caplog.records)
