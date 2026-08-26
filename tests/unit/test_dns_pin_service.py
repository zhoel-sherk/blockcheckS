"""Unit tests for DnsPinService (mocked IO, no netns)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.checkers.dns_secure import DnsRunCache
from blockchecks.engine.dns_pin_service import DnsPinService, pin_candidate_l3_ok

pytestmark = pytest.mark.unit


def _service(
    *,
    cache: DnsRunCache | None = None,
    pinned_path: str = "",
    probe: AsyncMock | None = None,
) -> tuple[DnsPinService, DnsRunCache, AsyncMock]:
    dns_cache = cache or DnsRunCache()
    probe_mock = probe or AsyncMock(return_value=True)
    svc = DnsPinService(
        dns_cache=dns_cache,
        pinned_path=pinned_path,
        acquire_ns=AsyncMock(return_value="bs-p-0"),
        release_ns=AsyncMock(),
    )
    svc.probe_pin_ip = probe_mock
    return svc, dns_cache, probe_mock


@pytest.mark.asyncio(loop_scope="package")
async def test_auto_pin_skips_when_no_domains():
    cache = DnsRunCache()
    svc, _, probe = _service(cache=cache)
    await svc.auto_pin_ips()
    probe.assert_not_called()


@pytest.mark.asyncio(loop_scope="package")
async def test_auto_pin_picks_first_working_candidate(tmp_path):
    path = str(tmp_path / "pins.conf")
    cache = DnsRunCache()
    cache.set("discord.com", ["162.159.136.232", "162.159.135.232"])

    async def _probe(domain: str, ip: str) -> bool:
        return ip == "162.159.135.232"

    svc, _, probe = _service(cache=cache, pinned_path=path)
    probe.side_effect = _probe

    with patch("blockchecks.engine.dns_pin_service.pin_candidate_l3_ok", return_value=True):
        await svc.auto_pin_ips()

    assert cache.primary_ip("discord.com") == "162.159.135.232"
    assert probe.await_count == 2


@pytest.mark.asyncio(loop_scope="package")
async def test_auto_pin_writes_only_when_changed(tmp_path):
    path = tmp_path / "pins.conf"
    path.write_text("162.159.135.232\tdiscord.com\n", encoding="utf-8")

    cache = DnsRunCache()
    cache.set("discord.com", ["162.159.136.232", "162.159.135.232"])
    cache.set_pins({"discord.com": "162.159.135.232"})

    svc, _, probe = _service(cache=cache, pinned_path=str(path))
    probe.return_value = True

    with patch("blockchecks.engine.dns_pin_service.pin_candidate_l3_ok", return_value=True):
        await svc.auto_pin_ips()
    unchanged = path.read_text(encoding="utf-8")

    async def _probe(domain: str, ip: str) -> bool:
        return ip == "162.159.136.232"

    probe.side_effect = _probe
    with patch("blockchecks.engine.dns_pin_service.pin_candidate_l3_ok", return_value=True):
        await svc.auto_pin_ips()
    updated = path.read_text(encoding="utf-8")

    assert unchanged == "162.159.135.232\tdiscord.com\n"
    assert "162.159.136.232\tdiscord.com" in updated


@pytest.mark.asyncio(loop_scope="package")
async def test_auto_pin_skips_l3_blocked_ips():
    cache = DnsRunCache()
    cache.set("example.com", ["192.0.2.1", "203.0.113.5"])
    svc, _, probe = _service(cache=cache)

    def _l3_ok(ip: str) -> bool:
        return ip == "203.0.113.5"

    with patch("blockchecks.engine.dns_pin_service.pin_candidate_l3_ok", side_effect=_l3_ok):
        await svc.auto_pin_ips()

    probe.assert_called_once_with("example.com", "203.0.113.5")


def test_pin_candidate_l3_ok_delegates_to_probe_l3():
    result = MagicMock()
    result.phase = "pass"
    with patch("blockchecks.checkers.l3_probe.probe_l3", return_value=result) as probe_l3:
        assert pin_candidate_l3_ok("1.2.3.4") is True
    probe_l3.assert_called_once()
