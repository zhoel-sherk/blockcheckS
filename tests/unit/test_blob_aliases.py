"""Unit tests for blob alias resolution (BLOB-3 / GV-5)."""

from __future__ import annotations

import pytest

from blockchecks.engine.blob_aliases import BLOB_ALIAS_MAP, resolve_blob_path

pytestmark = pytest.mark.unit


def test_blob_alias_map_has_tier1():
    assert BLOB_ALIAS_MAP["google"] == "tls_clienthello_www_google_com.bin"
    assert BLOB_ALIAS_MAP["quic_gv_kyber_1"] == "quic_gv_kyber_1.bin"


def test_resolve_google_alias(tmp_path):
    blobs = tmp_path / "blobs"
    blobs.mkdir()
    (blobs / "tls_clienthello_www_google_com.bin").write_bytes(b"x" * 10)
    path = resolve_blob_path("google", str(blobs))
    assert path and path.endswith("tls_clienthello_www_google_com.bin")


def test_resolve_builtin_returns_none():
    assert resolve_blob_path("fake_default_tls", "/nonexistent") is None


def test_resolve_quic_gv_from_fake_files(tmp_path):
    fake = tmp_path / "fake"
    fake.mkdir()
    src = fake / "quic_initial_rr1---sn-xguxaxjvh-n8me_googlevideo_com_kyber_1.bin"
    src.write_bytes(b"q" * 20)
    blobs = tmp_path / "blobs"
    blobs.mkdir()
    (blobs / "quic_gv_kyber_1.bin").symlink_to(src)
    path = resolve_blob_path("quic_gv_kyber_1", str(blobs))
    assert path and "kyber" in path
