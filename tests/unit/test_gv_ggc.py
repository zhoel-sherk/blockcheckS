"""GGC auto-fallback: googlevideo domains always use the deterministic GGC probe."""

from __future__ import annotations

import os

import pytest

from blockchecks.engine.config import ggc_enabled
from blockchecks.engine.domain_loader import auto_enable_gv_ggc

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("BLOCKCHECKS_GV_GGC", raising=False)


class TestGgcEnabled:
    def test_googlevideo_auto_fallback(self):
        assert ggc_enabled("googlevideo.com") is True

    def test_rr_subdomain_auto_fallback(self):
        assert ggc_enabled("rr5---sn-5goeenes.googlevideo.com") is True

    def test_non_googlevideo_disabled(self):
        assert ggc_enabled("discord.com") is False
        assert ggc_enabled("google.com") is False

    def test_none_disabled(self):
        assert ggc_enabled() is False

    def test_env_zero_opt_out(self, monkeypatch):
        monkeypatch.setenv("BLOCKCHECKS_GV_GGC", "0")
        assert ggc_enabled("googlevideo.com") is False

    def test_env_one_forced(self, monkeypatch):
        monkeypatch.setenv("BLOCKCHECKS_GV_GGC", "1")
        assert ggc_enabled("discord.com") is True


class TestAutoEnableGvGgc:
    def test_sets_env_when_googlevideo_present(self, monkeypatch):
        monkeypatch.delenv("BLOCKCHECKS_GV_GGC", raising=False)
        auto_enable_gv_ggc(["discord.com", "googlevideo.com"])
        assert os.environ.get("BLOCKCHECKS_GV_GGC") == "1"

    def test_no_env_without_googlevideo(self, monkeypatch):
        monkeypatch.delenv("BLOCKCHECKS_GV_GGC", raising=False)
        auto_enable_gv_ggc(["discord.com", "youtube.com"])
        assert os.environ.get("BLOCKCHECKS_GV_GGC") is None

    def test_respects_explicit_zero(self, monkeypatch):
        monkeypatch.setenv("BLOCKCHECKS_GV_GGC", "0")
        auto_enable_gv_ggc(["googlevideo.com"])
        assert os.environ.get("BLOCKCHECKS_GV_GGC") == "0"

    def test_preserves_existing_one(self, monkeypatch):
        monkeypatch.setenv("BLOCKCHECKS_GV_GGC", "1")
        auto_enable_gv_ggc(["googlevideo.com"])
        assert os.environ.get("BLOCKCHECKS_GV_GGC") == "1"
