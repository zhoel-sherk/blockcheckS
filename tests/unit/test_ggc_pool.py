"""ggc_pool: SNI-пул под управлением подборщика (synthetic/real/fixed)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture()
def pool_env(tmp_path: Path, monkeypatch):
    """Изолированный CACHE_DIR + чистый env на тест."""
    cache = tmp_path / "cache"
    cache.mkdir(parents=True)
    monkeypatch.setenv("BLOCKCHECKS_CACHE_HOME", str(cache))
    monkeypatch.delenv("BLOCKCHECKS_GGC_MODE", raising=False)
    monkeypatch.delenv("BLOCKCHECKS_GGC_IPS", raising=False)
    monkeypatch.delenv("BLOCKCHECKS_GGC_REAL_POOL", raising=False)
    monkeypatch.setattr(
        "blockchecks.engine.settings._load_user_toml", lambda path=None: {}
    )
    monkeypatch.setattr(
        "blockchecks.data_block.store.ProviderStore.load_dns_records_sync",
        lambda self: {},
    )

    from blockchecks.engine import ggc_pool as g
    from blockchecks.engine import paths as paths_mod

    monkeypatch.setattr(g, "CACHE_DIR", cache, raising=False)
    monkeypatch.setattr(g, "ips_cache_path", lambda: cache / "ggc_ips.json", raising=False)
    monkeypatch.setattr(
        g, "real_pool_path", lambda: cache / "ggc_real_hosts.json", raising=False
    )
    monkeypatch.setattr(paths_mod, "CACHE_DIR", cache, raising=False)
    g._ROTATION["i"] = 0
    yield g, cache


def test_synthetic_format_mimics_real(pool_env) -> None:
    g, _ = pool_env
    hosts = [g.generate_synthetic_host() for _ in range(500)]
    assert all(g.is_ggc_host(h) for h in hosts)
    # реальные образцы валидны тем же регексом
    for real in (
        "rr5---sn-5goeenes.googlevideo.com",
        "rr3---sn-1-ien47.googlevideo.com",
        "rr8---sn-uxaxjvh-30ze.googlevideo.com",
    ):
        assert g.is_ggc_host(real), real
    # мусор отсеивается
    assert not g.is_ggc_host("rr1---sn-.googlevideo.com")
    assert not g.is_ggc_host("youtube.com")


def test_no_immediate_repeat(pool_env) -> None:
    g, _ = pool_env
    import random

    random.seed(0)
    keys = []
    for _ in range(20):
        h = g.generate_synthetic_host()
        key = h.split("---")[0] + ":" + h.split("sn-")[1].split(".")[0]
        assert key not in keys[-8:]
        keys.append(key)


def test_real_pool_ttl_and_garbage(pool_env) -> None:
    g, cache = pool_env
    pp = cache / "ggc_real_hosts.json"
    pp.write_text(json.dumps({"timestamp": time.time() - 7 * 3600,
                              "hosts": ["rr5---sn-5goeenes.googlevideo.com"]}))
    assert g.load_real_pool() == []  # TTL 6ч
    pp.write_text(json.dumps({"timestamp": time.time(),
                              "hosts": ["rr5---sn-5goeenes.googlevideo.com", "мусор", 42]}))
    assert g.load_real_pool() == ["rr5---sn-5goeenes.googlevideo.com"]


def test_modes(pool_env, monkeypatch) -> None:
    g, cache = pool_env
    monkeypatch.setenv("BLOCKCHECKS_GGC_MODE", "fixed")
    t = g.pick_target()
    assert t.mode == "fixed" and t.host.endswith("googlevideo.com")

    (cache / "ggc_real_hosts.json").write_text(json.dumps(
        {"timestamp": time.time(), "hosts": ["rr2---sn-a5mek7k.googlevideo.com"]}))
    monkeypatch.setenv("BLOCKCHECKS_GGC_MODE", "real")
    t = g.pick_target()
    assert t.host == "rr2---sn-a5mek7k.googlevideo.com" and t.pool_size == 1

    # real с истёкшим пулом → fallback на synthetic
    (cache / "ggc_real_hosts.json").write_text(json.dumps({"timestamp": 0, "hosts": ["x"]}))
    t = g.pick_target()
    assert t.mode == "synthetic" or t.host.startswith("rr")

    monkeypatch.setenv("BLOCKCHECKS_GGC_MODE", "synthetic")
    assert g.pick_target().mode == "synthetic"


def test_ip_chain_order(pool_env, monkeypatch) -> None:
    g, cache = pool_env
    host = "rr5---sn-5goeenes.googlevideo.com"

    # пустые тиры → ротация по DEFAULT_LAST_RESORT_IPS (перебор при DNS-ошибках)
    assert (
        g.resolve_ip_chain("rr99---sn-unknown0.googlevideo.com")
        in g.DEFAULT_LAST_RESORT_IPS
    )
    # legacy-хост: ротация по живым edge (мёртвый 74.125.108.234 исключён)
    assert (g.resolve_ip_chain(host) or "") in g.DEFAULT_LAST_RESORT_IPS

    # кэш резолва приоритетнее legacy
    (cache / "ggc_ips.json").write_text(json.dumps(
        {"ips": {host: {"ip": "10.9.8.7", "ts": time.time()}}}))
    assert g.resolve_ip_chain(host) == "10.9.8.7"
    assert g.cached_ips() == ["10.9.8.7"]

    # env-список поверх кэша — голова стабильна (ротация только last-resort)
    monkeypatch.setenv("BLOCKCHECKS_GGC_IPS", "1.2.3.4, 5.6.7.8")
    assert g.configured_fallback_ips() == ["1.2.3.4", "5.6.7.8"]
    assert g.resolve_ip_chain("rr98---sn-zzzz9.googlevideo.com") == "1.2.3.4"


def test_dns_db_tier_beats_cache_and_env(pool_env, monkeypatch) -> None:
    g, cache = pool_env
    host = "rr5---sn-5goeenes.googlevideo.com"
    monkeypatch.setattr(
        "blockchecks.data_block.store.ProviderStore.load_dns_records_sync",
        lambda self: {host: (["198.51.100.7"], "doh")},
    )
    monkeypatch.setenv("BLOCKCHECKS_GGC_IPS", "1.2.3.4")
    (cache / "ggc_ips.json").write_text(
        json.dumps({"ips": {host: {"ip": "10.9.8.7", "ts": time.time()}}})
    )
    assert g.resolve_ip_chain(host) == "198.51.100.7"
    assert g.resolve_ip_chain("rr98---sn-zzzz9.googlevideo.com") == "1.2.3.4"


def test_last_resort_rotates(pool_env) -> None:
    g, _ = pool_env
    unknown = "rr99---sn-unknown0.googlevideo.com"
    n = len(g.DEFAULT_LAST_RESORT_IPS)
    got = [g.resolve_ip_chain(unknown) for _ in range(n + 1)]
    assert got == g.DEFAULT_LAST_RESORT_IPS + [g.DEFAULT_LAST_RESORT_IPS[0]]
    assert "74.125.108.234" not in got


def test_remember_ggc_ip_roundtrip(pool_env) -> None:
    g, cache = pool_env
    g.remember_ggc_ip("rr4---sn-xjvho9k.googlevideo.com", "203.0.113.5")
    g.remember_ggc_ip("не-ggc", "203.0.113.6")  # отброшен
    data = json.loads((cache / "ggc_ips.json").read_text())
    assert list(data["ips"]) == ["rr4---sn-xjvho9k.googlevideo.com"]
    assert g.cached_ips() == ["203.0.113.5"]


def test_pick_target_never_raises(pool_env, monkeypatch) -> None:
    g, _ = pool_env
    for mode in ("synthetic", "real", "fixed"):
        monkeypatch.setenv("BLOCKCHECKS_GGC_MODE", mode)
        t = g.pick_target()
        assert t.host and t.mode == mode


def test_current_mode_reads_toml_when_env_unset(pool_env, monkeypatch) -> None:
    g, _ = pool_env
    monkeypatch.delenv("BLOCKCHECKS_GGC_MODE", raising=False)
    monkeypatch.setattr(
        "blockchecks.engine.settings._load_user_toml",
        lambda path=None: {"google": {"mode": "fixed"}},
    )
    assert g.current_mode() == "fixed"
