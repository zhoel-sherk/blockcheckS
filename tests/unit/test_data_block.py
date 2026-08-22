"""Unit tests for data_block (provider slug, dns.db, strategies.db, hosts)."""

from pathlib import Path
from unittest.mock import MagicMock

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
        [
            {
                "domain": "signal.org",
                "udp_ips": "1.2.3.4",
                "doh_ips": "5.6.7.8",
                "verdict": "tampered",
            }
        ]
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
async def test_hosts_write_merges_existing_entries(store: ProviderStore):
    """A run that checks only some domains must not wipe unrelated hosts entries."""
    # Seed the hosts file with a pinned domain not in the new records.
    store.hosts_file.write_text(
        "162.159.137.232\tdiscord.com\n142.251.38.100\tgoogleapis.com\n",
        encoding="utf-8",
    )
    path = store.write_hosts({"discord.com": ["162.159.135.232"]})
    content = path.read_text()
    assert "162.159.135.232\tdiscord.com" in content  # updated IP
    assert "googleapis.com" in content  # unrelated entry preserved
    assert "142.251.38.100\tgoogleapis.com" in content


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


@pytest.mark.asyncio
async def test_pass_strategies_udp_does_not_clobber_tcp(store: ProviderStore):
    await store.upsert_pass_strategy(
        "fake:blob=stun:repeats=6",
        "discord.com",
        protocol="tcp",
        latency_ms=70,
        http_code=200,
    )
    await store.upsert_pass_strategy(
        "fake:blob=discord_udp:repeats=6",
        "35.217.5.42:50004",
        protocol="udp",
        latency_ms=12,
    )
    rows = await store.pass_strategies()
    by_proto = {r["protocol"]: r for r in rows}
    assert by_proto["tcp"]["domain"] == "discord.com"
    assert by_proto["udp"]["domain"] == "35.217.5.42:50004"
    assert by_proto["tcp"]["http_code"] == 200


@pytest.mark.unit
def test_best_config_write(store: ProviderStore):
    content = "# best config\n--lua-desync=fake\n"
    path = store.write_best_config(content)
    assert path.read_text() == content
    # unchanged content → no rewrite churn
    path2 = store.write_best_config(content)
    assert path2 == path


# ── provider_name resolution (network + config paths) ─────────────────


def test_provider_name_reads_cfg(monkeypatch, tmp_path):
    import blockchecks.data_block.provider as prov

    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    cfg_file = cfg_dir / "config.toml"
    cfg_file.write_text('[provider]\nname = "llc_trc_fiord"\n')
    monkeypatch.setattr(prov, "CONFIG_FILE", cfg_file)
    prov._CACHE.clear()
    assert prov.provider_name(allow_detect=False) == "llc_trc_fiord"


def test_provider_name_auto_detect_writes(monkeypatch, tmp_path):
    import blockchecks.data_block.provider as prov

    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    cfg_file = cfg_dir / "config.toml"
    monkeypatch.setattr(prov, "CONFIG_FILE", cfg_file)
    prov._CACHE.clear()
    monkeypatch.setattr(prov, "_query_ipinfo", lambda timeout=5.0: "My ISP LLC")
    name = prov.provider_name(allow_detect=True)
    assert name == "my_isp_llc"
    assert 'name = "my_isp_llc"' in cfg_file.read_text()


def test_provider_name_auto_detect_network_failure(monkeypatch, tmp_path):
    import blockchecks.data_block.provider as prov

    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    cfg_file = cfg_dir / "config.toml"
    monkeypatch.setattr(prov, "CONFIG_FILE", cfg_file)
    prov._CACHE.clear()
    monkeypatch.setattr(prov, "_query_ipinfo", lambda timeout=5.0: None)
    name = prov.provider_name(allow_detect=True)
    assert name == "default"
    assert not cfg_file.exists()  # default is not persisted


def test_get_provider_dir(monkeypatch, tmp_path):
    import blockchecks.data_block.provider as prov

    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    cfg_file = cfg_dir / "config.toml"
    cfg_file.write_text('[provider]\nname = "p1"\n')
    monkeypatch.setattr(prov, "CONFIG_FILE", cfg_file)
    monkeypatch.setenv("BLOCKCHECKS_DATA_BLOCK", str(tmp_path / "xdg-db"))
    monkeypatch.setattr(prov, "_repo_providers", lambda: None)
    prov._CACHE.clear()
    prov._MIGRATED = False
    d = prov.get_provider_dir(allow_detect=False)
    assert d == (tmp_path / "xdg-db" / "providers" / "p1")
    assert "p1" in str(d)


def test_runtime_root_ignores_sys_prefix(monkeypatch, tmp_path):
    import sys

    import blockchecks.data_block.provider as prov
    from blockchecks.engine.paths import DATA_DIR

    under = Path(sys.prefix) / "local" / "blockchecks-data"
    monkeypatch.setenv("BLOCKCHECKS_DATA_BLOCK", str(under))
    assert prov.data_block_runtime_root() == DATA_DIR / "data_block"
    monkeypatch.setenv("BLOCKCHECKS_DATA_BLOCK", str(tmp_path / "ok"))
    assert prov.data_block_runtime_root() == tmp_path / "ok"


# ── ProviderStore.sync_commit (git subprocess) ────────────────────────


def test_sync_commit_no_git_repo(tmp_path, store):
    assert store.sync_commit() is False


def test_sync_commit_git_success(store, tmp_path, monkeypatch):
    import subprocess

    repo = store._dir.parents[1]
    repo.mkdir(parents=True, exist_ok=True)
    (repo / ".git").mkdir()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: MagicMock(returncode=0))
    assert store.sync_commit(push=False) is True


def test_sync_commit_commit_failure(store, tmp_path, monkeypatch):
    import subprocess

    repo = store._dir.parents[1]
    repo.mkdir(parents=True, exist_ok=True)
    (repo / ".git").mkdir()
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: MagicMock(returncode=1, stdout="err", stderr="fail")
    )
    assert store.sync_commit(push=False) is False


# ── _query_ipinfo (network mocked) ────────────────────────────────────


def test_query_ipinfo_ok(monkeypatch):
    import json as _json

    import blockchecks.data_block.provider as prov

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return None

        def read(self):
            return _json.dumps({"org": "My ISP LLC"}).encode()

    monkeypatch.setattr(prov.urllib.request, "urlopen", lambda *a, **k: FakeResp())
    assert prov._query_ipinfo() == "My ISP LLC"


def test_query_ipinfo_no_org(monkeypatch):
    import blockchecks.data_block.provider as prov

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return None

        def read(self):
            return b'{"city": "x"}'

    monkeypatch.setattr(prov.urllib.request, "urlopen", lambda *a, **k: FakeResp())
    assert prov._query_ipinfo() is None


def test_query_ipinfo_error(monkeypatch):
    import urllib.error

    import blockchecks.data_block.provider as prov

    def boom(*a, **k):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(prov.urllib.request, "urlopen", boom)
    assert prov._query_ipinfo() is None


@pytest.mark.unit
def test_triage_toml_roundtrip(store: ProviderStore):
    from blockchecks.engine.triage import TriageProfile

    src = TriageProfile(
        silent_drop_after_sni=True,
        voice_ok=True,
        ech_blocked=False,
        viable_foolings=["tcp_ts=-1000"],
        viable_blobs=["stun", "tls_clienthello"],
        split_mode="sni_marker",
        server_hops=12,
        dpi_hops=3,
        autottl_delta=3,
        dead_foolings=["badsum", "send"],
    )
    path = store.save_triage(src, primary_domain="youtube.com")
    assert path.name == "triage.toml"
    text = path.read_text(encoding="utf-8")
    assert "null" not in text
    loaded = store.load_triage()
    assert loaded is not None
    assert loaded.silent_drop_after_sni is True
    assert loaded.voice_ok is True
    assert loaded.viable_foolings == ["tcp_ts=-1000"]
    assert loaded.dead_foolings == ["badsum", "send"]
    assert loaded.server_hops == 12
    assert loaded.split_mode == "sni_marker"


@pytest.mark.unit
def test_triage_toml_empty_dead_foolings_not_invented(store: ProviderStore):
    from blockchecks.engine.triage import TriageProfile

    text = store.save_triage(TriageProfile(), primary_domain="x.com").read_text(encoding="utf-8")
    assert "[dead]\nfoolings = []" in text
    assert "badsum" not in text
    loaded = store.load_triage()
    assert loaded is not None
    assert loaded.dead_foolings == []


@pytest.mark.unit
def test_triage_toml_clusters_csv_primary(store: ProviderStore):
    from blockchecks.engine.triage import TriageProfile

    drop = {"phase": "tls_silent_drop_after_sni", "prolog_ok": False, "silent_drop": True}
    src = TriageProfile(
        silent_drop_after_sni=True,
        domain_reports={
            "discord.com": dict(drop),
            "discord.gg": dict(drop),
            "storage.googleapis.com": {"phase": "pass", "prolog_ok": True},
        },
    )
    text = store.save_triage(src, primary_domain="discord.com").read_text(encoding="utf-8")
    assert 'primary_domain = "discord.com, discord.gg"' in text
    assert "[[cluster]]" in text
    assert "storage.googleapis.com" in text
    loaded = store.load_triage()
    assert loaded is not None
    assert loaded.silent_drop_after_sni is True


def test_migrate_provider_from_repo(monkeypatch, tmp_path):
    import blockchecks.data_block.provider as prov

    src = tmp_path / "repo" / "providers" / "isp"
    src.mkdir(parents=True)
    (src / "hosts").write_text("1.1.1.1\texample.com\n")
    xdg = tmp_path / "xdg-db"
    monkeypatch.setenv("BLOCKCHECKS_DATA_BLOCK", str(xdg))
    monkeypatch.setattr(prov, "_repo_providers", lambda: src.parent)
    monkeypatch.setattr(prov, "CONFIG_FILE", tmp_path / "cfg" / "config.toml")
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "config.toml").write_text('[provider]\nname = "isp"\n')
    prov._CACHE.clear()
    prov._MIGRATED = False
    dest = prov.get_provider_dir(allow_detect=False)
    assert dest == xdg / "providers" / "isp"
    assert (dest / "hosts").read_text() == "1.1.1.1\texample.com\n"


def test_export_copies_without_deleting_other_slugs(tmp_path, monkeypatch):
    import blockchecks.data_block.provider as prov
    from blockchecks.data_block.export import export_runtime_data_block

    runtime = tmp_path / "runtime"
    src = runtime / "providers" / "isp"
    src.mkdir(parents=True)
    (src / "hosts").write_text("9.9.9.9\tdiscord.com\n")
    dest_root = tmp_path / "dest"
    other = dest_root / "providers" / "other"
    other.mkdir(parents=True)
    (other / "hosts").write_text("keep-me\n")
    monkeypatch.setattr(prov, "data_block_runtime_root", lambda: runtime)
    n = export_runtime_data_block(dest_root)
    assert n == 1
    assert (dest_root / "providers" / "isp" / "hosts").read_text().startswith("9.9.9.9")
    assert (other / "hosts").read_text() == "keep-me\n"
    assert not (dest_root / "providers" / "default").exists()


def test_cmd_data_block_requires_out_when_no_git(monkeypatch, tmp_path):
    from argparse import Namespace

    from blockchecks.cli.commands.data_block import cmd_data_block
    from blockchecks.data_block import export as exp

    monkeypatch.setattr(exp, "default_export_dest", lambda: None)
    rc = cmd_data_block(Namespace(out=None, git=False, provider=None))
    assert rc == 1
    dest = tmp_path / "out"
    monkeypatch.setattr(exp, "export_runtime_data_block", lambda *_a, **_k: 1)
    rc = cmd_data_block(Namespace(out=str(dest), git=False, provider=None))
    assert rc == 0
