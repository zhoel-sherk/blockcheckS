"""Unit tests for data_block (provider slug, dns.db, strategies.db, hosts)."""

from pathlib import Path

import pytest

from blockchecks.data_block.provider import (
    DEFAULT_PROVIDER,
    normalize_provider_name,
)
from blockchecks.data_block.store import ProviderStore


@pytest.mark.unit
def test_normalize_provider_name():
    assert normalize_provider_name("AS51369 LLC TRC FIORD") == "llc_trc_fiord"
    assert normalize_provider_name("  AS1234   LLC   TRC   FIORD  ") == "llc_trc_fiord"
    assert normalize_provider_name("") == DEFAULT_PROVIDER
    assert normalize_provider_name(None) == DEFAULT_PROVIDER


@pytest.mark.unit
def test_normalize_provider_name_keeps_underscores():
    assert normalize_provider_name("Provider-One Two") == "provider_one_two"


@pytest.fixture
def store(tmp_path: Path) -> ProviderStore:
    return ProviderStore(tmp_path / "providers" / "testp")


@pytest.mark.unit
def test_provider_store_creates_md(store: ProviderStore):
    md = store.provider_dir / "testp.md"
    assert md.exists()
    assert "testp" in md.read_text()


@pytest.mark.asyncio
async def test_dns_records_roundtrip(store: ProviderStore):
    await store.save_dns_records(
        {"discord.com": ["162.159.128.232", "162.159.129.232"], "ripe.net": ["193.0.6.1"]}
    )
    recs = await store.load_dns_records()
    assert recs["discord.com"][0] == ["162.159.128.232", "162.159.129.232"]
    assert recs["ripe.net"][0] == ["193.0.6.1"]


@pytest.mark.asyncio
async def test_dns_records_upsert(store: ProviderStore):
    await store.save_dns_records({"discord.com": ["1.1.1.1"]})
    await store.save_dns_records({"discord.com": ["2.2.2.2"]})
    recs = await store.load_dns_records()
    assert recs["discord.com"][0] == ["2.2.2.2"]


@pytest.mark.asyncio
async def test_dns_tampered_rows(store: ProviderStore):
    await store.save_dns_tampered(
        [{"domain": "signal.org", "udp_ips": "1.2.3.4", "doh_ips": "5.6.7.8", "verdict": "tampered"}]
    )
    # tampered table exists and rows are inserted
    import aiosqlite

    async with aiosqlite.connect(store.dns_db) as db:
        cur = await db.execute("SELECT domain, verdict FROM dns_tampered")
        rows = await cur.fetchall()
    assert rows == [("signal.org", "tampered")]


@pytest.mark.asyncio
async def test_dns_records_sync_ttl(store: ProviderStore, monkeypatch):
    """Stale records (older than TTL) are filtered out by the sync reader."""
    await store.save_dns_records({"old.invalid": ["9.9.9.9"]})

    monkeypatch.setattr("blockchecks.data_block.store.DATA_BLOCK_DNS_TTL", 0)
    recs = store.load_dns_records_sync()
    assert "old.invalid" not in recs

    # fresh record still visible
    monkeypatch.setattr("blockchecks.data_block.store.DATA_BLOCK_DNS_TTL", 7 * 86400)
    recs = store.load_dns_records_sync()
    assert "old.invalid" in recs


@pytest.mark.asyncio
async def test_hosts_file_generation(store: ProviderStore):
    await store.save_dns_records({"discord.com": ["162.159.128.232", "1.1.1.1"]})
    recs = store.load_dns_records_sync()
    path = store.write_hosts(recs)
    assert path.exists()
    content = path.read_text()
    assert "162.159.128.232\tdiscord.com" in content
    assert "1.1.1.1" not in content  # only first IP per domain


@pytest.mark.asyncio
async def test_pass_strategies_roundtrip(store: ProviderStore):
    await store.upsert_pass_strategy(
        "fake:blob=stun:repeats=6:tcp_ts=-1000",
        "discord.com",
        protocol="tcp",
        latency_ms=107,
        http_code=200,
        approved=True,
    )
    await store.upsert_pass_strategy(
        "fake:blob=stun:repeats=6:tcp_ts=-1000",
        "youtube.com",
        protocol="tcp",
        latency_ms=120,
        http_code=200,
    )
    approved = await store.pass_strategies(approved_only=True)
    assert len(approved) == 1
    assert approved[0]["strategy"].startswith("fake:")
    all_rows = await store.pass_strategies()
    assert len(all_rows) == 2


@pytest.mark.asyncio
async def test_pass_strategies_upsert_updates(store: ProviderStore):
    await store.upsert_pass_strategy("strategy_a", "d.com", protocol="tcp", latency_ms=200)
    await store.upsert_pass_strategy("strategy_a", "d.com", protocol="tcp", latency_ms=100)
    rows = await store.pass_strategies()
    assert len(rows) == 1
    assert rows[0]["latency_ms"] == 100


@pytest.mark.unit
def test_best_config_write(store: ProviderStore):
    content = "# best config\n--lua-desync=fake\n"
    path = store.write_best_config(content)
    assert path.read_text() == content
    # unchanged content → no rewrite churn
    path2 = store.write_best_config(content)
    assert path2 == path
