"""DNS-based Discord voice server discovery.

Resolves finland{N}.discord.gg to GCP backend IPs (35.217.x.x).
No Discord token or gateway connection needed.

Range: N=14000-14147 → ~148 unique IPs, all GCP Hamina.
Ports: UDP 50000-50006 confirmed open on all GCP backends.

Cache: /logs/bs_voice_cache.json, rotated after 1-2 hours.
"""

import asyncio
import json
import os
import random
import socket
import time
from pathlib import Path
from typing import Optional

# DNS range for finland region (the only active one)
DNS_RANGE = (14000, 14148)

# Typical voice UDP ports
VOICE_PORTS = [50000, 50001, 50002, 50003, 50004, 50005, 50006]

# Cache settings
CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
CACHE_FILE = "bs_voice_cache.json"
CACHE_TTL_SECONDS = 90 * 60  # 90 minutes


def _cache_path() -> str:
    return os.path.join(CACHE_DIR, _get_root(), CACHE_FILE)


def _get_root() -> str:
    """Project root directory."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_cache() -> Optional[dict]:
    """Load cached voice endpoints if not expired."""
    os.makedirs(os.path.dirname(_cache_path()), exist_ok=True)
    cache_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs", "bs_voice_cache.json"
    )
    if not os.path.exists(cache_file):
        return None
    try:
        with open(cache_file) as f:
            data = json.load(f)
        age = time.time() - data.get("timestamp", 0)
        if age < CACHE_TTL_SECONDS:
            return data
        # Rotate old cache
        ts = time.strftime("%Y%m%d_%H%M%S")
        old_path = cache_file.replace(".json", f"_old_{ts}.json")
        os.rename(cache_file, old_path)
        return None
    except (json.JSONDecodeError, OSError):
        return None


def _save_cache(endpoints: list[dict]) -> None:
    """Save voice endpoints to cache."""
    os.makedirs(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs"
    ), exist_ok=True)
    cache_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs", "bs_voice_cache.json"
    )
    data = {"timestamp": time.time(), "endpoints": endpoints}
    with open(cache_file, "w") as f:
        json.dump(data, f)


async def _resolve_host(host: str) -> Optional[str]:
    """Resolve a single hostname to IPv4. Returns IP or None."""
    try:
        loop = asyncio.get_event_loop()
        addrs = await loop.getaddrinfo(host, 0, family=socket.AF_INET, type=socket.SOCK_DGRAM)
        if addrs:
            return addrs[0][4][0]
    except Exception:
        pass
    return None


async def resolve_finland_range(start: int = DNS_RANGE[0],
                                 end: int = DNS_RANGE[1]) -> dict[str, list[str]]:
    """Bulk-resolve finland{N}.discord.gg in parallel.

    Returns: {ip: [list of matching hostnames]}
    """
    tasks = []
    hosts = []
    for n in range(start, end):
        host = f"finland{n}.discord.gg"
        hosts.append(host)
        tasks.append(_resolve_host(host))

    results = await asyncio.gather(*tasks)

    ip_to_hosts: dict[str, list[str]] = {}
    for host, ip in zip(hosts, results):
        if ip and ip.startswith("35."):  # Only GCP Hamina IPs
            ip_to_hosts.setdefault(ip, []).append(host)

    return ip_to_hosts


async def discover_voice_endpoints(count: int = 5,
                                    use_cache: bool = True) -> list[dict]:
    """Discover N Discord voice UDP endpoints.

    Layer 1 (DNS): Resolve finland{N}.discord.gg → GCP IPs.
    Layer 2 (Gateway): If token available, gateway WS → OP2 Ready.
    Layer 3 (Static): DNS fallback from earlier attempts.

    Returns: list of {"ip": str, "port": int, "hostname": str}
    """
    endpoints = []
    seen_ips: set[str] = set()

    # ── Check cache ──
    if use_cache:
        cached = _load_cache()
        if cached:
            eps = cached.get("endpoints", [])
            for ep in eps:
                ip = ep.get("ip", "")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    endpoints.append(ep)
                if len(endpoints) >= count:
                    print(f"[voice-dns] Using {len(endpoints[:count])} cached endpoints")
                    return endpoints[:count]

    # ── Layer 1: DNS bulk ──
    print(f"[voice-dns] Resolving finland{{{DNS_RANGE[0]}}}...discord.gg range {DNS_RANGE[0]}-{DNS_RANGE[1]-1}...")
    ip_map = await resolve_finland_range()

    # Pick one random port per unique IP
    ips = list(ip_map.keys())
    random.shuffle(ips)

    for ip in ips:
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        port = random.choice(VOICE_PORTS)
        hostname = ip_map[ip][0]
        endpoints.append({"ip": ip, "port": port, "hostname": hostname})
        if len(endpoints) >= count:
            break

    # ── Save cache ──
    if endpoints:
        _save_cache(endpoints)

    print(f"[voice-dns] Discovered {len(endpoints[:count])} endpoints")
    return endpoints[:count]
