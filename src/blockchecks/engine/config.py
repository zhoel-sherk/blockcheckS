"""blockcheckS shared configuration — paths, constants, defaults.

Uses BLOCKCHECKS_* env vars for portable paths. Falls back to sensible defaults.
"""

import os
import sys
import time
from pathlib import Path

# ── Resolvable paths ─────────────────────────────

_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
_PACKAGE_DIR = os.path.dirname(_ENGINE_DIR)  # .../blockchecks
_PARENT = os.path.dirname(_PACKAGE_DIR)  # .../src or site-packages
_REPO_CANDIDATE = os.path.dirname(_PARENT)  # repo root (editable src layout)


def _resolve_project_dir() -> str:
    """Repo root (editable) or package dir (wheel with packaged configs).

    Wheel data (blobs/configs/lua via [tool.setuptools.data-files]) lands under
    ``sys.prefix/blockchecks`` (PEP 427 install scheme), not inside
    site-packages — check it as a fallback so a plain ``pip install`` wheel is
    self-sufficient.
    """
    candidates = [_REPO_CANDIDATE, _PARENT, _PACKAGE_DIR]
    if sys.prefix != _PARENT:
        candidates.append(os.path.join(sys.prefix, "blockchecks"))
    for candidate in candidates:
        if os.path.isdir(os.path.join(candidate, "configs")):
            return candidate
    # Editable src/ layout without relying on configs/
    if os.path.basename(_PARENT) == "src":
        return _REPO_CANDIDATE
    return _PACKAGE_DIR


PROJECT_DIR = _resolve_project_dir()
PACKAGE_DIR = _PACKAGE_DIR
CONFIGS_DIR = os.path.join(PROJECT_DIR, "configs")
REPO_BLOBS_DIR = os.path.join(PROJECT_DIR, "blobs")
REPO_LUA_DIR = os.path.join(PROJECT_DIR, "lua", "blockchecks")
_BLOCKCHECKS_LUA_NAMES = ("write_ipc.lua", "scan_bridge.lua", "init.lua")


def _env_or(key, default: str) -> str:
    return os.environ.get(key, default)


# External tool paths
_DEFAULT_NFQWS2 = "/opt/zapret2/nfq2/nfqws2"
_DEFAULT_LUA = "/opt/zapret2/lua"
_LUA_SCRIPT_NAMES = ("zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua")


def _default_blobs_dir() -> str:
    """Prefer in-repo baked blobs/; then /opt/zapret2/blobs."""
    if os.path.isdir(REPO_BLOBS_DIR) and any(
        name.endswith(".bin") for name in os.listdir(REPO_BLOBS_DIR)
    ):
        return REPO_BLOBS_DIR
    return "/opt/zapret2/blobs"


NFQWS2_BIN = _env_or("BLOCKCHECKS_NFQWS2", _DEFAULT_NFQWS2)
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

# Blob directory — repo blobs/ by default (baked); override with BLOCKCHECKS_BLOBS
BLOB_DIR = _env_or("BLOCKCHECKS_BLOBS", _default_blobs_dir())

# Lua init scripts (env: BLOCKCHECKS_LUA_DIR)
LUA_INIT_DIR = _env_or("BLOCKCHECKS_LUA_DIR", _DEFAULT_LUA)
LUA_INIT_SCRIPTS = [os.path.join(LUA_INIT_DIR, f) for f in _LUA_SCRIPT_NAMES]


def get_lua_init_scripts(extra: list[str] | None = None) -> list[str]:
    """Return zapret lua-init paths plus optional extras and BLOCKCHECKS_LUA_EXTRA."""
    paths = [os.path.join(LUA_INIT_DIR, f) for f in _LUA_SCRIPT_NAMES]
    if extra:
        paths.extend(extra)
    extra_env = os.environ.get("BLOCKCHECKS_LUA_EXTRA", "").strip()
    if extra_env:
        for part in extra_env.split(":"):
            p = part.strip()
            if p:
                paths.append(p)
    return paths


def get_blockchecks_lua_scripts(extra: list[str] | None = None) -> list[Path]:
    """Paths to repo lua/blockchecks/*.lua for bridge init chain."""
    out: list[Path] = []
    for name in _BLOCKCHECKS_LUA_NAMES:
        p = Path(REPO_LUA_DIR) / name
        if p.is_file():
            out.append(p)
    if extra:
        for e in extra:
            ep = Path(e)
            if ep.is_file():
                out.append(ep)
    extra_env = os.environ.get("BLOCKCHECKS_LUA_EXTRA", "").strip()
    if extra_env:
        for part in extra_env.split(":"):
            p = Path(part.strip())
            if p.is_file():
                out.append(p)
    return out


def get_nfqws2_bin() -> str:
    """Return current nfqws2 path (env override or module constant)."""
    return os.environ.get("BLOCKCHECKS_NFQWS2") or NFQWS2_BIN


def apply_tool_paths(
    *,
    nfqws2: str | None = None,
    blobs: str | None = None,
    lua_dir: str | None = None,
) -> None:
    """Refresh module-level tool paths after vendor install or config.toml.

    Also updates ``os.environ`` so child processes inherit the same layout.
    """
    global NFQWS2_BIN, BLOB_DIR, LUA_INIT_DIR, LUA_INIT_SCRIPTS

    if nfqws2:
        os.environ["BLOCKCHECKS_NFQWS2"] = nfqws2
        NFQWS2_BIN = nfqws2
    else:
        NFQWS2_BIN = os.environ.get("BLOCKCHECKS_NFQWS2", NFQWS2_BIN)

    if blobs:
        os.environ["BLOCKCHECKS_BLOBS"] = blobs
        BLOB_DIR = blobs
    else:
        BLOB_DIR = os.environ.get("BLOCKCHECKS_BLOBS", BLOB_DIR)

    if lua_dir:
        os.environ["BLOCKCHECKS_LUA_DIR"] = lua_dir
        LUA_INIT_DIR = lua_dir
    else:
        LUA_INIT_DIR = os.environ.get("BLOCKCHECKS_LUA_DIR", LUA_INIT_DIR)

    LUA_INIT_SCRIPTS = [os.path.join(LUA_INIT_DIR, f) for f in _LUA_SCRIPT_NAMES]


# Network isolation
NFQUEUE_TCP = int(_env_or("BLOCKCHECKS_QNUM_TCP", "200"))
NFQUEUE_UDP = int(_env_or("BLOCKCHECKS_QNUM_UDP", "201"))
NETNS_BASE = _env_or("BLOCKCHECKS_NETNS_BASE", "bs-p")
DEFAULT_POOL_SIZE = int(_env_or("BLOCKCHECKS_POOL", "4"))

# Lua bridge (/dev/shm IPC)
SHM_BASE = _env_or("BLOCKCHECKS_SHM_BASE", "/dev/shm/blockchecks")
DEFAULT_BRIDGE_BATCH = int(_env_or("BLOCKCHECKS_BRIDGE_BATCH", "500"))
DEFAULT_BRIDGE_BATCH_MAX = int(_env_or("BLOCKCHECKS_BRIDGE_BATCH_MAX", "2000"))

DEFAULT_PROBE_BACKEND = "lua_bridge"  # T-L3: lua_bridge is the standard backend


def resolve_probe_backend(args) -> str:
    """Resolve probe backend from flags/env (T-L3/T-L4/T-L5).

    Precedence: ``--classic`` > ``--probe-backend`` > ``--lua-bridge`` >
    ``BLOCKCHECKS_PROBE_BACKEND`` > default ``lua_bridge``.

    Returns one of ``"classic"`` / ``"lua_bridge"``.
    """
    if getattr(args, "classic", False):
        return "classic"
    pb = getattr(args, "probe_backend", None)
    if pb in ("classic", "lua_bridge"):
        return pb
    if getattr(args, "lua_bridge", False):
        return "lua_bridge"
    env = os.environ.get("BLOCKCHECKS_PROBE_BACKEND", "").strip().lower()
    if env in ("classic", "lua_bridge"):
        return env
    return DEFAULT_PROBE_BACKEND


def effective_default_pool_size(*, mem_soft_cap_kb: int = 1_500_000) -> int:
    """CLI default for ``--parallel``: env/DEFAULT_POOL_SIZE, soft-capped on low RAM.

    If MemAvailable < ~1.5 GiB (Pi2-class), default to 1 and leave a WARNING to stderr
    when the uncapped value would have been higher.
    """
    base = max(1, int(DEFAULT_POOL_SIZE))
    avail = None
    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    avail = int(line.split()[1])
                    break
    except (OSError, ValueError):
        avail = None
    if avail is not None and avail < mem_soft_cap_kb and base > 1:
        _warn_mem_low(avail, mem_soft_cap_kb, base)
        return 1
    return base


_mem_warned: bool = False


def _warn_mem_low(avail: int, cap: int, base: int) -> None:
    global _mem_warned
    if _mem_warned:
        return
    _mem_warned = True
    import sys

    print(
        f"  WARNING: MemAvailable={avail} kB < {cap}; "
        f"default --parallel capped {base} → 1 (override with --parallel)",
        file=sys.stderr,
    )


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


def refresh_secure_dns_from_env() -> None:
    """Re-read SECURE_DNS / DoH after settings/config.toml applied env."""
    global SECURE_DNS_DEFAULT, DEFAULT_DOH_SERVER
    SECURE_DNS_DEFAULT = _env_bool("BLOCKCHECKS_SECURE_DNS", True)
    DEFAULT_DOH_SERVER = os.environ.get("BLOCKCHECKS_DOH_SERVER", "").strip()


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
UNBLOCKED_DOM = _env_or("BLOCKCHECKS_UNBLOCKED_DOM", "ripe.net")

# Fallback reference hosts: tried in order when the primary UNBLOCKED_DOM is
# unreachable (ISP blocks / geo), or used via cached IP when DNS itself fails.
UNBLOCKED_DOMS = [
    d.strip()
    for d in os.environ.get(
        "BLOCKCHECKS_UNBLOCKED_DOMS",
        "ripe.net,cloudflare.com,about.rdap.org,iana.org",
    ).split(",")
    if d.strip()
]

# Content validation thresholds
MIN_CONTENT_LENGTH = 300  # bytes — minimum for a real web page (aligned with tcp_tls)
MIN_READ_RATE_BPS = 500.0  # bytes/sec — below this = TCP window clamp (FAIL)
THROTTLED_MAX_BPS = 256000.0  # bytes/sec — below this (but >= MIN) = THROTTLED
MIN_REDIRECT_LENGTH = 10  # bytes — redirects have tiny bodies, don't fail them

# ── googlevideo.com CDN testing ──────────────────
# Range request size — just above 16KB TSPU buffer threshold
GOOGLEVIDEO_RANGE_SIZE = 17408  # 17KB, bytes=0-17407

# Deterministic GGC probe (no yt-dlp signature): hit a live Google cache IP with
# SNI=rr*.googlevideo.com and a 1MB Range to trigger the TSPU "video download"
# heuristic. CDN responding (any HTTP) == bypassed; timeout == blocked.
GGC_RANGE_SIZE = 1048576  # 1MiB, bytes=0-1048575
GGC_HOST = _env_or("BLOCKCHECKS_GGC_HOST", "rr5---sn-5goeenes.googlevideo.com")
GGC_FALLBACK_IP = _env_or("BLOCKCHECKS_GGC_IP", "74.125.108.234")
GGC_ENABLED = _env_bool("BLOCKCHECKS_GV_GGC", False)

# ── ECH (Encrypted Client Hello) ──────────────────
# Disable ECH via curl_cffi.CurlOpt.ECH = 10325
# Forces plaintext SNI in ClientHello — testable by standard DPI strategies
CURLOPT_ECH = 10325

# ── nfqws2 settle / readiness (Phase 11 B1) ───────
NFQWS2_SETTLE_MAX = float(_env_or("BLOCKCHECKS_NFQWS2_SETTLE_MAX", "0.5"))
NFQWS2_SETTLE_POLL = float(_env_or("BLOCKCHECKS_NFQWS2_SETTLE_POLL", "0.05"))
NFQWS2_SETTLE_MIN = float(_env_or("BLOCKCHECKS_NFQWS2_SETTLE_MIN", "0"))

# ── memory monitor / daemon recycle (services.metrics) ───────
# RSS ceiling for an nfqws2 daemon (MiB); recycle when exceeded.
MEM_MONITOR_MAX_MIB = float(_env_or("BLOCKCHECKS_MEM_MAX_MIB", "512"))
# Leak slope threshold (MiB/s over the sampling window); recycle when exceeded.
MEM_MONITOR_LEAK_SLOPE = float(_env_or("BLOCKCHECKS_MEM_LEAK_SLOPE", "8"))
# RSS ceiling for the Python worker (MiB); log warning (no recycle — process owner).
MEM_MONITOR_PY_MAX_MIB = float(_env_or("BLOCKCHECKS_MEM_PY_MAX_MIB", "2048"))
# Sampling window size (samples) for the sliding-window slope estimate.
MEM_MONITOR_WINDOW = int(_env_or("BLOCKCHECKS_MEM_WINDOW", "12"))
# Poll interval seconds for periodic checks inside long bridge runs.
MEM_MONITOR_POLL = float(_env_or("BLOCKCHECKS_MEM_POLL", "2.0"))
# Enable the monitor entirely (0 disables all sampling/recycle).
MEM_MONITOR_ENABLED = _env_bool("BLOCKCHECKS_MEM_MONITOR", True)

# ── multi-domain curl fan-out (Phase 11 B2) ───────
DEFAULT_CURL_PARALLEL = int(_env_or("BLOCKCHECKS_CURL_PARALLEL", "1"))
MAX_CURL_PARALLEL = int(_env_or("BLOCKCHECKS_CURL_PARALLEL_MAX", "8"))

# ── nfqws2 debug ─────────────────────────────────
# BLOCKCHECKS_NFQWS2_DEBUG: empty/0=off, 1=file under logs/, syslog, @path, or path
NFQWS2_DEBUG = os.environ.get("BLOCKCHECKS_NFQWS2_DEBUG", "").strip()

from blockchecks.engine.paths import RUNTIME_LOGS_DIR  # noqa: E402

# str alias for os.path.join / makedirs; Path source is RUNTIME_LOGS_DIR
LOGS_DIR = str(RUNTIME_LOGS_DIR)


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
