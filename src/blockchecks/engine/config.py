"""blockcheckS shared configuration — paths, constants, defaults.

Uses BLOCKCHECKS_* env vars for portable paths. Falls back to sensible defaults.
"""

import os

# ── Resolvable paths ─────────────────────────────

_ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
_PACKAGE_DIR = os.path.dirname(_ENGINE_DIR)          # .../blockchecks
_PARENT = os.path.dirname(_PACKAGE_DIR)              # .../src or site-packages
_REPO_CANDIDATE = os.path.dirname(_PARENT)           # repo root (editable src layout)


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
NFQWS2_BIN       = _env_or("BLOCKCHECKS_NFQWS2", "/opt/zapret2/nfq2/nfqws2")
SING_BOX_BIN     = _env_or("BLOCKCHECKS_SINGBOX", "/usr/local/bin/sing-box")
SING_BOX_CONFIG  = os.environ.get("BLOCKCHECKS_SINGBOX_CONFIG",
                    os.path.expanduser("~/.config/sing-box/config.json"))

# Python venv
PYTHON_BIN       = _env_or("BLOCKCHECKS_PYTHON", os.path.join(PROJECT_DIR, ".venv/bin/python"))
# Fallback if local .venv doesn't exist — use system or dpi-tester venv
for _path in [PYTHON_BIN,
              "/home/zhoel/workspace/dpi-tester/.venv/bin/python",
              os.path.join(PROJECT_DIR, "../dpi-tester/.venv/bin/python")]:
    if os.path.exists(_path):
        PYTHON_BIN = _path
        break

# Discord token source
DPI_TESTER_SETTINGS = _env_or("BLOCKCHECKS_SETTINGS",
    os.path.join(PROJECT_DIR, "../dpi-tester/settings.ini"))

# Blob directory
BLOB_DIR          = _env_or("BLOCKCHECKS_BLOBS", "/opt/zapret2/blobs")

# Lua init scripts
LUA_INIT_DIR      = "/opt/zapret2/lua"
LUA_INIT_SCRIPTS  = [os.path.join(LUA_INIT_DIR, f) for f in
                     ("zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua")]

# Network isolation
NFQUEUE_TCP       = int(_env_or("BLOCKCHECKS_QNUM_TCP", "200"))
NFQUEUE_UDP       = int(_env_or("BLOCKCHECKS_QNUM_UDP", "201"))
NETNS_BASE        = _env_or("BLOCKCHECKS_NETNS_BASE", "bs-p")
DEFAULT_POOL_SIZE = int(_env_or("BLOCKCHECKS_POOL", "4"))

# Sing-box SOCKS5 proxy
SOCKS5_PROXY      = _env_or("BLOCKCHECKS_PROXY", "socks5://127.0.0.1:11080")

# Default voice targets (will be overridden by auto-discovery)
DEFAULT_VOICE_IP   = "35.217.5.42"
DEFAULT_VOICE_PORT = 50006

# Content validation thresholds
MIN_CONTENT_LENGTH = 300    # bytes — minimum for a real web page (aligned with tcp_tls)
MIN_READ_RATE_BPS  = 500.0  # bytes/sec — below this = TCP window clamp
MIN_REDIRECT_LENGTH = 10    # bytes — redirects have tiny bodies, don't fail them
