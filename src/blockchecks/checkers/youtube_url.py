"""YouTube googlevideo.com URL fetcher via yt-dlp.

Fetches fresh, signed googlevideo.com URLs for CDN testing.
Cache: 3-hour TTL in XDG cache (bs_gv_url_cache.json)
"""

import json
import os
import subprocess
import time

from blockchecks.engine.paths import GV_URL_CACHE_FILE

CACHE_TTL = 3 * 3600  # 3 hours (googlevideo URLs expire in ~6 hours)


def _signed_url_ip_family(url: str) -> str | None:
    """Return 'v4' / 'v6' from videoplayback ``ip=`` param, or None if absent."""
    from urllib.parse import parse_qs, unquote, urlparse

    ip = parse_qs(urlparse(url).query).get("ip", [""])[0]
    if not ip:
        return None
    return "v6" if ":" in unquote(ip) else "v4"


def _cache_entry_valid(data: dict) -> bool:
    url = data.get("url") or ""
    if "googlevideo.com" not in url:
        return False
    if time.time() - data.get("timestamp", 0) >= CACHE_TTL:
        return False
    # Signed URLs bind to client IP; IPv6-bound URLs 403 on IPv4-only egress.
    return _signed_url_ip_family(url) != "v6"


def _cache_path() -> str:
    GV_URL_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    return str(GV_URL_CACHE_FILE)


def get_fresh_url(
    video_id: str = "dQw4w9WgXcQ",
    format_code: str = "18",
    proxy: str | None = None,
) -> str | None:
    """Get a fresh googlevideo.com URL for testing.

    Uses yt-dlp to extract the direct video stream URL.
    Cached for 3 hours to avoid repeated API calls.

    Args:
        video_id: YouTube video ID (default: Rick Roll — always available)
        format_code: yt-dlp format (18 = 360p mp4)
        proxy: optional SOCKS5 proxy (e.g., socks5://127.0.0.1:11080)
    Returns:
        Fresh googlevideo.com URL or None if unavailable.
    """
    cache_file = _cache_path()

    # Check cache
    if os.path.exists(cache_file):
        try:
            with open(cache_file) as f:
                data = json.load(f)
            if _cache_entry_valid(data):
                return data.get("url")
        except (json.JSONDecodeError, KeyError):
            pass

    # Fetch fresh URL
    import shutil

    from blockchecks.engine.config import PROJECT_DIR, YTDLP_BIN

    ytdlp = YTDLP_BIN or shutil.which("yt-dlp")
    if not ytdlp:
        candidate = os.path.join(PROJECT_DIR, ".venv", "bin", "yt-dlp")
        if os.path.exists(candidate):
            ytdlp = candidate
    if not ytdlp:
        return None
    if not ytdlp:
        return None

    from blockchecks.engine.config import SOCKS5_PROXY

    proxies = []
    if proxy:
        proxies.append(proxy)
    else:
        proxies.append(None)
        if SOCKS5_PROXY:
            proxies.append(SOCKS5_PROXY)

    for px in proxies:
        url = _fetch_ytdlp_url(ytdlp, video_id, format_code, proxy=px)
        if url:
            with open(cache_file, "w") as f:
                json.dump(
                    {
                        "timestamp": time.time(),
                        "url": url,
                        "video_id": video_id,
                        "proxy": px or "",
                    },
                    f,
                )
            return url

    # Fallback: return cached URL even if expired (skip IPv6-bound entries)
    if os.path.exists(cache_file):
        try:
            with open(cache_file) as f:
                data = json.load(f)
            url = data.get("url")
            if url and _signed_url_ip_family(url) != "v6":
                return url
        except (json.JSONDecodeError, KeyError):
            pass

    return None


def _fetch_ytdlp_url(
    ytdlp: str,
    video_id: str,
    format_code: str,
    *,
    proxy: str | None = None,
) -> str | None:
    cmd = [
        ytdlp,
        "--force-ipv4",
        "-g",
        "-f",
        format_code,
        f"https://www.youtube.com/watch?v={video_id}",
    ]
    if proxy:
        cmd[1:1] = ["--proxy", proxy]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        urls = [
            line.strip()
            for line in r.stdout.splitlines()
            if line.startswith("https://") and "googlevideo.com" in line
        ]
        if urls:
            url = urls[0]
            if _signed_url_ip_family(url) == "v6":
                return None
            return url
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def has_fresh_url() -> bool:
    """Check if cached URL is still fresh."""
    cache_file = _cache_path()
    if not os.path.exists(cache_file):
        return False
    try:
        with open(cache_file) as f:
            data = json.load(f)
        return _cache_entry_valid(data)
    except (json.JSONDecodeError, KeyError):
        return False


def videoplayback_host(url: str) -> str:
    """Extract hostname from a signed googlevideo videoplayback URL."""
    from urllib.parse import urlparse

    return (urlparse(url).hostname or "").lower()
