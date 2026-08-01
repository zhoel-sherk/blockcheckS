"""Unit tests for Phase 11 B11 settle profile."""

import json
from pathlib import Path

from blockchecks.engine.settle_profile import (
    SettleProfile,
    TimingOverride,
    build_profile_from_rows,
    load_profile,
    save_profile,
)


def test_build_profile_picks_min_settle():
    rows = [
        {
            "strategy_full": "fake:blob=stun:repeats=6",
            "settle_max": 1.0,
            "curl_t": 2.0,
            "ok": True,
        },
        {
            "strategy_full": "fake:blob=stun:repeats=6",
            "settle_max": 0.2,
            "curl_t": 1.5,
            "ok": True,
        },
        {
            "strategy_full": "fake:blob=stun:repeats=6",
            "settle_max": 0.1,
            "curl_t": 0.5,
            "ok": False,
        },
    ]
    profile = build_profile_from_rows(rows, domain="discord.com")
    o = profile.lookup("fake:blob=stun:repeats=6")
    assert o is not None
    assert o.settle_max == 0.2
    assert o.curl_timeout == 1.5
    assert profile.defaults is not None
    assert profile.defaults.settle_max == 0.2


def test_save_load_roundtrip(tmp_path: Path):
    profile = SettleProfile(
        domain="discord.com",
        defaults=TimingOverride(0.2, 1.5),
        strategies={"fake:blob=stun": TimingOverride(0.1, 1.0)},
    )
    path = str(tmp_path / "settle_profile.json")
    save_profile(profile, path)
    loaded = load_profile(path)
    assert loaded is not None
    assert loaded.domain == "discord.com"
    assert loaded.defaults.curl_timeout == 1.5
    assert loaded.lookup("fake:blob=stun").settle_max == 0.1
    with open(path) as f:
        data = json.load(f)
    assert data["version"] == 1
