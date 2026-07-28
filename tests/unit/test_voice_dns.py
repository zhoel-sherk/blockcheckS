"""Tests for voice DNS discovery."""
import os, sys, pytest, asyncio
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from checkers.voice_dns import discover_voice_endpoints, _load_cache, _save_cache


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


def test_cache_save_and_load():
    """Cache can be saved and reloaded."""
    test_eps = [{"ip": "35.217.1.1", "port": 50004, "hostname": "test.example.com"}]
    _save_cache(test_eps)
    cached = _load_cache()
    if cached:
        assert "endpoints" in cached
        assert len(cached["endpoints"]) >= 1


@pytest.mark.asyncio
async def test_discovery_uses_cache():
    """Second call uses cache (much faster)."""
    import time
    # Force fresh discovery first
    await discover_voice_endpoints(1, use_cache=False)
    # Second call should use cache
    t0 = time.perf_counter()
    eps = await discover_voice_endpoints(1, use_cache=True)
    elapsed = time.perf_counter() - t0
    assert len(eps) >= 1
    assert elapsed < 1.0, f"Cache load too slow: {elapsed:.2f}s"
</tz-doc>

cat > /home/zhoel/workspace/blockcheckS/tmp-scripts/README.md << 'EOF'
# tmp-scripts — blockcheckS research & test scripts

## Voice discovery

```bash
# Test DNS discovery
python3 -c "
import asyncio, sys
sys.path.insert(0, '.')
from checkers.voice_dns import discover_voice_endpoints
eps = asyncio.run(discover_voice_endpoints(5, use_cache=False))
for e in eps: print(f'{e[\"ip\"]}:{e[\"port\"]} ({e[\"hostname\"]})')
"

# --auto-discover N pair test
sudo python3 bs.py pair -d discord.com \
  --generate fake_multi --max 3 \
  --auto-discover 3 --parallel 4

# Cache: logs/bs_voice_cache.json (90min TTL)
# Rotated: bs_voice_cache_old_<date>.json when expired
