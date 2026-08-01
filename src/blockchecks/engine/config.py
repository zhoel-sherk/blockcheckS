"""blockcheckS shared configuration — paths, constants, defaults.

Uses BLOCKCHECKS_* env vars for portable paths. Falls back to sensible defaults.
"""

import os
import sys
import time

# ── Resolvable paths ─────────────────────────────

_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
_PACKAGE_DIR = os.path.dirname(_ENGINE_DIR)  # .../blockchecks
_PARENT = os.path.dirname(_PACKAGE_DIR)  # .../src or site-packages
_REPO_CANDIDATE = os.path.dirname(_PARENT)  # repo root (editable src layout)


def _resolve_project_dir() -> str:
    """Repo root (editable) or package dir (wheel with packaged configs)."""
    for candidate in (_REPO_CANDIDATE, _PARENT, _PACKAGE_DIR):
        if os.path.isdir(os.path.join(candidate, "configs")):
            return candidate
    # Editable src/ layout without relying on configs/
    if os.path.basename(_PARENT) == "src":
        return _REPO_CANDIDATE
    return _PACKAGE_DIR


PROJECT_DIR = _resolve_project_dir()
PACKAGE_DIR = _PACKAGE_DIR
CONFIGS_DIR = os.path.join(PROJECT_DIR, "configs")


def _env_or(key, default: str) -> str:
    return os.environ.get(key, default)


# External tool paths
NFQWS2_BIN = _env_or("BLOCKCHECKS_NFQWS2", "/opt/zapret2/nfq2/nfqws2")
SING_BOX_BIN = _env_or("BLOCKCHECKS_SINGBOX", "/usr/local/bin/sing-box")
SING_BOX_CONFIG = os.environ.get(
    "BLOCKCHECKS_SINGBOX_CONFIG", os.path.expanduser("~/.config/sing-box/config.json")
)

# Python interpreter for netns subprocess probes
def _resolve_python() -> str:
    explicit = os.environ.get("BLOCKCHECKS_PYTHON")
    if explicit:
        return explicit
    for candidate in (
        os.path.join(PROJECT_DIR, ".venv/bin/python"),
        os.path.normpath(os.path.join(PROJECT_DIR, "../dpi-tester/.venv/bin/python")),
    ):
        if os.path.exists(candidate):
            return candidate
    return sys.executable


PYTHON_BIN = _resolve_python()

# yt-dlp binary (googlevideo URL fetch — GV-1)
YTDLP_BIN = _env_or("BLOCKCHECKS_YTDLP", "")

DPI_TESTER_SETTINGS = _env_or(
    "BLOCKCHECKS_SETTINGS", os.path.join(PROJECT_DIR, "../dpi-tester/settings.ini")
)

# Blob directory
BLOB_DIR = _env_or("BLOCKCHECKS_BLOBS", "/opt/zapret2/blobs")

# Lua init scripts
LUA_INIT_DIR = "/opt/zapret2/lua"
LUA_INIT_SCRIPTS = [
    os.path.join(LUA_INIT_DIR, f)
    for f in ("zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua")
]

# Network isolation
NFQUEUE_TCP = int(_env_or("BLOCKCHECKS_QNUM_TCP", "200"))
NFQUEUE_UDP = int(_env_or("BLOCKCHECKS_QNUM_UDP", "201"))
NETNS_BASE = _env_or("BLOCKCHECKS_NETNS_BASE", "bs-p")
DEFAULT_POOL_SIZE = int(_env_or("BLOCKCHECKS_POOL", "4"))

# Sing-box SOCKS5 proxy
SOCKS5_PROXY = _env_or("BLOCKCHECKS_PROXY", "socks5://127.0.0.1:11080")

# Secure DNS (Phase 9 SD)
def _env_bool(key: str, default: bool) -> bool:
    v = os.environ.get(key)
    if v is None:
        return default
    return v.strip().lower() not in ("0", "false", "off", "no")


SECURE_DNS_DEFAULT = _env_bool("BLOCKCHECKS_SECURE_DNS", True)
DEFAULT_DOH_SERVER = os.environ.get("BLOCKCHECKS_DOH_SERVER", "").strip()
DNS_CACHE_TTL = float(_env_or("BLOCKCHECKS_DNS_CACHE_TTL", "3600"))

DOH_SERVERS = [
    ("https://cloudflare-dns.com/dns-query", "Cloudflare"),
    ("https://dns.google/dns-query", "Google"),
    ("https://dns.quad9.net/dns-query", "Quad9"),
    ("https://dns.adguard-dns.com/dns-query", "AdGuard"),
    ("https://dns.yandex.ru/dns-query", "Yandex"),
]
UDP_DNS_SERVERS = [
    ("8.8.8.8", "Google"),
    ("1.1.1.1", "Cloudflare"),
    ("9.9.9.9", "Quad9"),
]

# Default voice targets (will be overridden by auto-discovery)
DEFAULT_VOICE_IP = "35.217.5.42"
DEFAULT_VOICE_PORT = 50006

# IP-block cross-test reference host (blockcheck2 UNBLOCKED_DOM)
UNBLOCKED_DOM = _env_or("BLOCKCHECKS_UNBLOCKED_DOM", "iana.org")

# Content validation thresholds
MIN_CONTENT_LENGTH = 300  # bytes — minimum for a real web page (aligned with tcp_tls)
MIN_READ_RATE_BPS = 500.0  # bytes/sec — below this = TCP window clamp (FAIL)
THROTTLED_MAX_BPS = 256000.0  # bytes/sec — below this (but >= MIN) = THROTTLED
MIN_REDIRECT_LENGTH = 10  # bytes — redirects have tiny bodies, don't fail them

# ── googlevideo.com CDN testing ──────────────────
# Range request size — just above 16KB TSPU buffer threshold
GOOGLEVIDEO_RANGE_SIZE = 17408  # 17KB, bytes=0-17407

# ── ECH (Encrypted Client Hello) ──────────────────
# Disable ECH via curl_cffi.CurlOpt.ECH = 10325
# Forces plaintext SNI in ClientHello — testable by standard DPI strategies
CURLOPT_ECH = 10325

# ── nfqws2 settle / readiness (Phase 11 B1) ───────
NFQWS2_SETTLE_MAX = float(_env_or("BLOCKCHECKS_NFQWS2_SETTLE_MAX", "2.0"))
NFQWS2_SETTLE_POLL = float(_env_or("BLOCKCHECKS_NFQWS2_SETTLE_POLL", "0.1"))
NFQWS2_SETTLE_MIN = float(_env_or("BLOCKCHECKS_NFQWS2_SETTLE_MIN", "0.05"))

# ── nfqws2 debug ─────────────────────────────────
# BLOCKCHECKS_NFQWS2_DEBUG: empty/0=off, 1=file under logs/, syslog, @path, or path
NFQWS2_DEBUG = os.environ.get("BLOCKCHECKS_NFQWS2_DEBUG", "").strip()
LOGS_DIR = os.path.join(PROJECT_DIR, "logs")


def nfqws2_debug_conf_line(tag: str = "") -> tuple[str | None, str | None]:
    """Build a conf ``--debug=…`` line from env.

    Returns ``(conf_line_or_None, log_path_or_None)``.
    When enabled as ``1``, writes under ``logs/nfqws2_<tag>_<pid>.log``.
    """
    v = os.environ.get("BLOCKCHECKS_NFQWS2_DEBUG", NFQWS2_DEBUG).strip()
    if not v or v.lower() in ("0", "false", "off", "no"):
        return None, None
    if v.lower() in ("1", "true", "on", "yes"):
        os.makedirs(LOGS_DIR, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in (tag or "run"))[:40]
        path = os.path.join(
            LOGS_DIR, f"nfqws2_{safe}_{os.getpid()}_{int(time.time() * 1000) % 1000000}.log"
        )
        return f"--debug=@{path}", path
    if v.lower() == "syslog":
        return "--debug=syslog", None
    if v.startswith("@"):
        return f"--debug={v}", v[1:]
    return f"--debug=@{v}", v
