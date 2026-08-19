"""DNS-based Discord voice server discovery.

Resolves finland{N}.discord.gg to GCP backend IPs (35.217.x.x).
No Discord token or gateway connection needed.

Also seeds candidates from Maks-gaming discord-servers (daily bot lists)
and filters with STUN liveness via discover_dns_alive().

Range: N=14000-14147 → ~148 unique IPs, all GCP Hamina.
Ports: UDP 50000-50006 confirmed open on all GCP backends.

Cache: XDG cache bs_voice_cache.json, rotated after 1-2 hours.
"""

import asyncio
import json
import os
import random
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import contextmanager

from blockchecks.engine.paths import VOICE_DNS_CACHE_FILE

# DNS range for finland region (the only active one)
DNS_RANGE = (14000, 14148)

# Typical voice UDP ports
VOICE_PORTS = [50000, 50001, 50002, 50003, 50004, 50005, 50006]

# Maks-gaming discord-servers (daily GitHub Actions refresh)
# Region-specific list; not every region is published under regions/ (russia /
# frankfurt 404) — fall back to the global all-regions list below.
MAKS_IP_LIST_URL = (
    "https://raw.githubusercontent.com/Maks-gaming/discord-servers/main"
    "/regions/{region}/{region}-voice-ip-list.txt"
)
MAKS_GLOBAL_IP_LIST_URL = (
    "https://raw.githubusercontent.com/Maks-gaming/discord-servers/main"
    "/data/voice-ip-list.txt"
)
# Region-prefixed hostnames (finland14000.discord.gg, frankfurt14000…) — used to
# pick the region's endpoints out of the global list via DNS re-resolution.
MAKS_GLOBAL_DOMAIN_LIST_URL = (
    "https://raw.githubusercontent.com/Maks-gaming/discord-servers/main"
    "/data/voice-domain-list.txt"
)

# Region prefixes → hostname prefixes in the domain list
REGION_HOST_PREFIXES = {
    "russia": "russia",
    "frankfurt": "frankfurt",
    "finland": "finland",
    "warsaw": "warsaw",
    "stockholm": "stockholm",
    "us-east": "useast",
}

# Cache settings — XDG cache
CACHE_TTL_SECONDS = 90 * 60  # 90 minutes


def _cache_file_path() -> str:
    return str(VOICE_DNS_CACHE_FILE)


def _ensure_cache_dir() -> None:
    VOICE_DNS_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)


# Parallel probes through host NFQUEUE+bootstrap; >4 tends to queue-bypass
# drop replies (remote throttling: 8→0/64 alive, 4→3/4 ip_discovery).
STUN_PROBE_CONCURRENCY = 4


def _cache_file() -> str:
    return _cache_file_path()


def _load_cache() -> dict | None:
    """Load cached voice endpoints if not expired."""
    cache_file = _cache_file()
    _ensure_cache_dir()
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
    _ensure_cache_dir()
    data = {"timestamp": time.time(), "endpoints": endpoints}
    with open(_cache_file(), "w") as f:
        json.dump(data, f)


async def _resolve_host(host: str, sem: asyncio.Semaphore | None = None) -> str | None:
    """Resolve a single hostname to IPv4. Returns IP or None."""
    try:
        if sem:
            async with sem:
                loop = asyncio.get_event_loop()
                addrs = await loop.getaddrinfo(
                    host, 0, family=socket.AF_INET, type=socket.SOCK_DGRAM
                )
        else:
            loop = asyncio.get_event_loop()
            addrs = await loop.getaddrinfo(host, 0, family=socket.AF_INET, type=socket.SOCK_DGRAM)
        if addrs:
            return addrs[0][4][0]
    except Exception:
        pass
    return None


async def resolve_finland_range(
    start: int = DNS_RANGE[0],
    end: int = DNS_RANGE[1],
    max_concurrent: int = 32,
) -> dict[str, list[str]]:
    """Bulk-resolve finland{N}.discord.gg in parallel.

    Returns: {ip: [list of matching hostnames]}
    """
    sem = asyncio.Semaphore(max_concurrent)
    tasks = []
    hosts = []
    for n in range(start, end):
        host = f"finland{n}.discord.gg"
        hosts.append(host)
        tasks.append(_resolve_host(host, sem=sem))

    results = await asyncio.gather(*tasks)

    ip_to_hosts: dict[str, list[str]] = {}
    for host, ip in zip(hosts, results):
        if ip and ip.startswith("35."):  # Only GCP Hamina IPs
            ip_to_hosts.setdefault(ip, []).append(host)

    return ip_to_hosts


async def discover_voice_endpoints(count: int = 5, use_cache: bool = True) -> list[dict]:
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
    print(
        f"[voice-dns] Resolving finland{{{DNS_RANGE[0]}}}...discord.gg range {DNS_RANGE[0]}-{DNS_RANGE[1] - 1}..."
    )
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


def positive_discover_count(value) -> int | None:
    """Return N when discover flag is set to a positive int; else None.

    ``None`` / ``False`` / ``0`` / non-int → do not run discovery.
    """
    if value is None or value is False:
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def check_discover_mutex(discover_dns, auto_discover) -> str | None:
    """Return error message if both discover flags are set, else None."""
    dns_on = positive_discover_count(discover_dns) is not None
    auto_on = positive_discover_count(auto_discover) is not None
    if dns_on and auto_on:
        return (
            "ERROR: --discover-dns and --auto-discover are mutually exclusive "
            "(dns-alive vs VPN/gateway path)"
        )
    return None


def resolve_voice_targets(
    voice_ip: str,
    voice_port: int,
    multi_eps: list | None = None,
) -> list[tuple[str, int]]:
    """Return (ip, port) list for pair/udp fan-out (V2-1).

    Prefers ``multi_eps`` when non-empty; otherwise a single ``(voice_ip, voice_port)``.
    """
    out: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for ep in multi_eps or []:
        if not isinstance(ep, dict):
            continue
        ip = ep.get("ip")
        port = ep.get("port")
        if not ip or port is None:
            continue
        key = (str(ip), int(port))
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    if out:
        return out
    return [(str(voice_ip), int(voice_port))]


def pair_log_domain(domain: str, ip: str, port: int, *, multi: bool) -> str:
    """Domain key for pair_results resume when fan-out across endpoints."""
    if multi:
        return f"{domain}@{ip}:{port}"
    return domain


def parse_maks_ip_list(text: str) -> list[str]:
    """Parse one-IP-per-line text from Maks-gaming voice ip lists."""
    ips: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(".")
        if len(parts) != 4:
            continue
        try:
            if not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                continue
        except ValueError:
            continue
        if line not in seen:
            seen.add(line)
            ips.append(line)
    return ips


def _maks_get(url: str, timeout: float) -> str | None:
    """GET a Maks-gaming raw file; None on any error."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "blockcheckS"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def fetch_maks_voice_ips(region: str = "finland", timeout: float = 5.0) -> list[str]:
    """Fetch voice IPs from Maks-gaming discord-servers. Soft-fail → [].

    Tries the region-specific list first; when the region is not published under
    ``regions/`` (russia / frankfurt 404), falls back to the global
    ``data/voice-ip-list.txt`` (all regions).
    """
    text = _maks_get(MAKS_IP_LIST_URL.format(region=region), timeout)
    if text is None:
        text = _maks_get(MAKS_GLOBAL_IP_LIST_URL, timeout)
        if text is not None:
            print(f"[voice-dns] Maks-gaming ({region}): region 404 → global list")
    if text is None:
        print("[voice-dns] Maks-gaming fetch failed (continuing with DNS)")
        return []
    ips = parse_maks_ip_list(text)
    print(f"[voice-dns] Maks-gaming ({region}): {len(ips)} IPs")
    return ips


def fetch_maks_region_ips(region: str = "russia", timeout: float = 8.0) -> list[str]:
    """Fetch a region's voice IPs via the global domain list + DNS.

    ``data/voice-domain-list.txt`` lists hosts like ``russia14000.discord.gg`` /
    ``frankfurt14000.discord.gg``. We resolve the region-prefixed hosts to IPs
    and return the unique set. This covers regions missing from ``regions/``.
    """
    text = _maks_get(MAKS_GLOBAL_DOMAIN_LIST_URL, timeout)
    if not text:
        return []
    prefix = REGION_HOST_PREFIXES.get(region, region)
    hosts: list[str] = []
    for line in text.splitlines():
        line = line.strip().lower()
        if line.startswith(prefix) and line.endswith(".discord.gg"):
            hosts.append(line)
    if not hosts:
        print(f"[voice-dns] Maks-gaming region '{region}': no matching hosts")
        return []

    async def _resolve_all():
        sem = asyncio.Semaphore(32)
        return await asyncio.gather(*(_resolve_host(h, sem=sem) for h in hosts))

    results = asyncio.run(_resolve_all())
    ips: list[str] = []
    seen: set[str] = set()
    for ip in results:
        if ip and ip not in seen:
            seen.add(ip)
            ips.append(ip)
    print(f"[voice-dns] Maks-gaming ({region}): {len(ips)} IPs from {len(hosts)} hosts")
    return ips


@contextmanager
def udp_discover_bootstrap(
    enabled: bool = True,
    strategy: str = "fake:blob=discord_udp:repeats=6",
    qnum: int | None = None,
):
    """Temporarily run nfqws2 UDP desync + iptables for discover probes.

    Yields True if bootstrap is active, False if skipped/failed (probes still run).
    Always cleans up in finally. No-op on non-Linux or enabled=False.
    """
    if not enabled or sys.platform != "linux":
        yield False
        return

    from blockchecks.engine.config import (
        BLOB_DIR,
        NFQUEUE_UDP,
        get_lua_init_scripts,
        nfqws2_debug_conf_line,
    )
    from blockchecks.service.firewall import Firewall
    from blockchecks.service.nfqws2 import Nfqws2Manager

    q = NFQUEUE_UDP if qnum is None else qnum
    fw = Firewall()
    mgr = Nfqws2Manager(qnum=q)
    conf_path: str | None = None
    active = False
    try:
        lines = [
            f"--qnum={q}",
            "--filter-udp=50000-50100",
            "--filter-l3=ipv4",
            "--ipcache-lifetime=0",
            "--bind-fix4",
        ]
        dbg, _dbg_path = nfqws2_debug_conf_line(tag="discover-boot")
        if dbg:
            lines.append(dbg)
        for lua in get_lua_init_scripts():
            if os.path.exists(lua):
                lines.append(f"--lua-init=@{lua}")
        blob = os.path.join(BLOB_DIR, "discord_udp.bin")
        if os.path.exists(blob):
            lines.append(f"--blob=discord_udp:@{blob}")
        lines.append(f"--lua-desync={strategy}")

        fd, conf_path = tempfile.mkstemp(prefix="bs_discover_udp_", suffix=".conf")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.chmod(conf_path, 0o644)

        fw.prepare_udp(ports="50000:50100", qnum=q)
        mgr.start_config(conf_path)
        active = True
        print(f"[voice-dns] Bootstrap nfqws2 UDP active (qnum={q}, {strategy})")
        yield True
    except Exception as e:
        print(f"[voice-dns] Bootstrap failed (probing without nfqws2): {e}")
        yield False
    finally:
        try:
            mgr.stop()
        except Exception:
            pass
        try:
            fw.cleanup()
        except Exception:
            pass
        if conf_path:
            try:
                os.unlink(conf_path)
            except OSError:
                pass
        if active:
            print("[voice-dns] Bootstrap nfqws2 stopped")


async def discover_dns_alive(
    count: int = 5,
    *,
    candidates: int = 64,
    stun_timeout: float = 1.0,
    use_cache: bool = True,
    use_maks: bool = True,
    region: str = "finland",
    use_bootstrap: bool = True,
    try_burst: bool = False,
    stop_event: asyncio.Event | None = None,
) -> list[dict]:
    """Discover voice endpoints via DNS + Maks seed, filtered by dual UDP probe.

    No VPN/sing-box. On Linux, optionally wraps probes in nfqws2 UDP bootstrap
    so DPI-blocked STUN/IP-discovery can still get replies.

    Returns only endpoints that answer, or [].
    Each dict: ip, port, hostname, source, stun_ms, method, bootstrap.
    """
    from blockchecks.checkers.udp_voice import voice_udp_probe

    meta: dict[str, dict] = {}
    dns_seed = 0
    maks_seed = 0

    def _add(ip: str, *, hostname: str, source: str, port: int | None = None) -> None:
        if not ip or ip in meta:
            return
        meta[ip] = {
            "ip": ip,
            "port": port if port is not None else random.choice(VOICE_PORTS),
            "hostname": hostname,
            "source": source,
        }

    if use_cache:
        cached = _load_cache()
        if cached:
            for ep in cached.get("endpoints", []):
                ip = ep.get("ip", "")
                if not ip:
                    continue
                _add(
                    ip,
                    hostname=ep.get("hostname", ""),
                    source="cache-alive",
                    port=ep.get("port"),
                )

    print(
        f"[voice-dns] Resolving finland{{{DNS_RANGE[0]}}}...discord.gg "
        f"range {DNS_RANGE[0]}-{DNS_RANGE[1] - 1}..."
    )
    ip_map = await resolve_finland_range()
    dns_ips = list(ip_map.keys())
    random.shuffle(dns_ips)
    for ip in dns_ips:
        before = len(meta)
        _add(ip, hostname=ip_map[ip][0], source="dns-alive")
        if len(meta) > before:
            dns_seed += 1

    if use_maks:
        # Region-specific endpoints (russia/frankfurt via domain list) first;
        # fall back to the region IP list (or its global fallback).
        region_ips = await asyncio.to_thread(fetch_maks_region_ips, region)
        if region_ips:
            random.shuffle(region_ips)
            for ip in region_ips:
                before = len(meta)
                _add(ip, hostname=f"maks:{region}", source="maks-region")
                if len(meta) > before:
                    maks_seed += 1
        else:
            maks_ips = await asyncio.to_thread(fetch_maks_voice_ips, region)
            random.shuffle(maks_ips)
            for ip in maks_ips:
                before = len(meta)
                _add(ip, hostname=f"maks:{region}", source="maks-alive")
                if len(meta) > before:
                    maks_seed += 1

    ordered = list(meta.values())[:candidates]
    if not ordered:
        print("[voice-dns] No DNS/Maks candidates to probe")
        return []

    sem = asyncio.Semaphore(STUN_PROBE_CONCURRENCY)
    print(
        f"[voice-dns] Dual-probing {len(ordered)} candidates "
        f"(dns+={dns_seed} maks+={maks_seed}, "
        f"concurrency={STUN_PROBE_CONCURRENCY}, bootstrap={use_bootstrap})..."
    )

    with udp_discover_bootstrap(enabled=use_bootstrap) as boot_on:

        async def _probe(ep: dict) -> dict | None:
            async with sem:
                try:
                    ok, ms, _detail, method = await asyncio.wait_for(
                        asyncio.to_thread(
                            voice_udp_probe,
                            ep["ip"],
                            ep["port"],
                            stun_timeout,
                            try_burst=try_burst,
                        ),
                        timeout=stun_timeout * 2 + 1.0,
                    )
                except asyncio.TimeoutError:
                    return None
                if not ok:
                    return None
                out = dict(ep)
                out["stun_ms"] = round(ms, 1)
                out["method"] = method
                out["bootstrap"] = boot_on
                return out

        results: list[dict | None] = []
        tasks = [asyncio.ensure_future(_probe(ep)) for ep in ordered]
        try:
            while tasks:
                if stop_event is not None and stop_event.is_set():
                    for t in tasks:
                        t.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    break
                done, pending = await asyncio.wait(
                    tasks, return_when=asyncio.FIRST_COMPLETED
                )
                results.extend(t.result() for t in done)
                tasks = list(pending)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    alive = [r for r in results if r is not None][:count]

    if alive:
        _save_cache(alive)

    methods = sorted({a.get("method", "") for a in alive if a.get("method")})
    print(
        f"[voice-dns] dns-alive: {len(alive)}/{len(ordered)} probed "
        f"(dns={dns_seed} maks={maks_seed}, bootstrap={boot_on}, "
        f"methods={methods or ['none']})"
    )
    return alive
