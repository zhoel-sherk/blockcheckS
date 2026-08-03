"""Wave3 audit regressions: H2/H3/H4/H6/H8/migrate."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from blockchecks.checkers.dns_secure import DnsRunCache
from blockchecks.engine.adaptive_queue import AdaptiveJob, AdaptiveJobQueue
from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.paths import migrate_legacy_state_db
from blockchecks.engine.preflight import PreflightOptions, run_prolog


@pytest.mark.unit
@pytest.mark.asyncio
async def test_filter_resume_gather(monkeypatch):
    q = AdaptiveJobQueue()
    item = StrategyItem("a", "fake:repeats=1")
    for dom in ("x.com", "y.com", "z.com"):
        q.enqueue(AdaptiveJob.from_item(item, dom))

    calls: list[str] = []

    async def check(job):
        calls.append(job.domain)
        await asyncio.sleep(0.01)
        return job.domain == "y.com"

    skipped = await q.filter_resume(check)
    assert skipped == 1
    assert set(calls) == {"x.com", "y.com", "z.com"}
    assert ("a", "y.com") not in q._pending


@pytest.mark.unit
def test_doh_rotate_on_failure(monkeypatch):
    cache = DnsRunCache(doh_server="https://bad.example/dns-query")
    seq = [
        ([], "fail", 1.0),
        (["1.2.3.4"], "", 1.0),
    ]

    def fake_doh(domain, url, timeout=5.0):
        return seq.pop(0)

    monkeypatch.setattr(
        "blockchecks.checkers.dns_secure.DOH_SERVERS",
        [
            ("https://bad.example/dns-query", "bad"),
            ("https://good.example/dns-query", "good"),
        ],
    )
    monkeypatch.setattr("blockchecks.checkers.dns_secure.doh_query", fake_doh)
    ips = cache.resolve("discord.com")
    assert ips == ["1.2.3.4"]
    assert cache.doh_server == "https://good.example/dns-query"


@pytest.mark.unit
def test_run_prolog_passes_verify_content():
    with patch("blockchecks.engine.preflight.check_tls") as tls:
        tls.return_value = MagicMock(success=True)
        assert run_prolog("iana.org", verify_content=True) is True
        assert tls.call_args.kwargs["verify_content"] is True


@pytest.mark.unit
def test_preflight_options_has_verify_content():
    assert PreflightOptions().verify_content is False


@pytest.mark.unit
def test_migrate_legacy_state_db(tmp_path, monkeypatch):
    legacy = tmp_path / "state.db"
    legacy.write_bytes(b"sqlite")
    dest = tmp_path / "xdg" / "state.db"
    monkeypatch.setattr("blockchecks.engine.paths.DEFAULT_DB_PATH", dest)
    monkeypatch.setattr(
        "blockchecks.engine.paths.ensure_dirs",
        lambda: dest.parent.mkdir(parents=True, exist_ok=True),
    )
    monkeypatch.setattr("blockchecks.engine.paths.reclaim_sudo_ownership", lambda p: None)
    assert migrate_legacy_state_db(cwd=tmp_path) == dest
    assert dest.read_bytes() == b"sqlite"
    # second call no-op
    assert migrate_legacy_state_db(cwd=tmp_path) is None


@pytest.mark.unit
def test_singbox_lock_exists():
    from blockchecks.checkers import voice_discovery as vd

    assert hasattr(vd, "_singbox_lock")


@pytest.mark.unit
def test_export_configs_accepts_store():
    import inspect

    from blockchecks.nfconf import export_configs

    assert "store" in inspect.signature(export_configs).parameters
