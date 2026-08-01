"""YouTube googlevideo.com URL fetcher via yt-dlp.

Fetches fresh, signed googlevideo.com URLs for CDN testing.
Cache: 3-hour TTL in PROJECT_DIR/logs/bs_gv_url_cache.json
"""

import json
import os
import subprocess
import time

CACHE_FILE = "bs_gv_url_cache.json"
CACHE_TTL = 3 * 3600  # 3 hours (googlevideo URLs expire in ~6 hours)


def _cache_path() -> str:
    from blockchecks.engine.config import PROJECT_DIR

    os.makedirs(os.path.join(PROJECT_DIR, "logs"), exist_ok=True)
    return os.path.join(PROJECT_DIR, "logs", CACHE_FILE)


def get_fresh_url(
    video_id: str = "dQw4w9WgXcQ", format_code: str = "18", proxy: str | None = None
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
            if time.time() - data.get("timestamp", 0) < CACHE_TTL:
                url = data.get("url")
                if url and "googlevideo.com" in url:
                    return url
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
    cmd = [ytdlp, "-g", "-f", format_code, f"https://www.youtube.com/watch?v={video_id}"]
    if proxy:
        cmd.insert(1, proxy)
        cmd.insert(1, "--proxy")

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        urls = [
            line.strip()
            for line in r.stdout.splitlines()
            if line.startswith("https://") and "googlevideo.com" in line
        ]
        if urls:
            url = urls[0]
            with open(cache_file, "w") as f:
                json.dump({"timestamp": time.time(), "url": url, "video_id": video_id}, f)
            return url
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Fallback: return cached URL even if expired
    if os.path.exists(cache_file):
        try:
            with open(cache_file) as f:
                data = json.load(f)
            return data.get("url")
        except (json.JSONDecodeError, KeyError):
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
        return time.time() - data.get("timestamp", 0) < CACHE_TTL
    except (json.JSONDecodeError, KeyError):
        return False


def videoplayback_host(url: str) -> str:
    """Extract hostname from a signed googlevideo videoplayback URL."""
    from urllib.parse import urlparse

    return (urlparse(url).hostname or "").lower()
