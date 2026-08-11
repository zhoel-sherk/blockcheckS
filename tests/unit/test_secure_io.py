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
