"""Tests for voice DNS discovery."""
import os, sys, pytest, asyncio, time

from blockchecks.checkers.voice_dns import discover_voice_endpoints


@pytest.mark.asyncio
async def test_dns_discovery_discovers_endpoints():
    """DNS discovery finds at least 1 GCP endpoint."""
    eps = await discover_voice_endpoints(3, use_cache=False)
    assert len(eps) >= 1, f"Should find at least 1 endpoint, got {len(eps)}"
    for ep in eps:
        assert ep["ip"].startswith("35."), f"Expected GCP IP, got {ep['ip']}"
        assert 50000 <= ep["port"] <= 50006, f"Port out of range: {ep['port']}"


@pytest.mark.asyncio
async def test_dns_discovery_no_duplicates():
    """DNS discovery returns unique IPs."""
    eps = await discover_voice_endpoints(10, use_cache=False)
    ips = [ep["ip"] for ep in eps]
    assert len(ips) == len(set(ips)), f"Duplicate IPs found: {ips}"
