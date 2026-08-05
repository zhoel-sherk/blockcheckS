"""System dependency checks and optional zapret2 vendor install (1.0.1).

Resolves nfqws2 from env / PATH / /opt / XDG DATA_DIR, and can download the
official bol-van/zapret2 release into ``~/.local/share/blockcheckS/zapret2``.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from blockchecks.engine import config as cfg
from blockchecks.engine.paths import CACHE_DIR, DATA_DIR, ensure_dirs

ZAPRET2_REPO = "bol-van/zapret2"
GITHUB_API_LATEST = f"https://api.github.com/repos/{ZAPRET2_REPO}/releases/latest"
USER_AGENT = "blockcheckS/1.0.2 (+https://github.com/zhoel-sherk/blockcheckS)"

VENDOR_ROOT = DATA_DIR / "zapret2"
VENDOR_BIN_LINK = DATA_DIR / "bin" / "nfqws2"
DL_CACHE = CACHE_DIR / "zapret2-dl"

# platform.machine() → zapret2 binaries/ folder
_ARCH_MAP = {
    "x86_64": "linux-x86_64",
    "amd64": "linux-x86_64",
    "aarch64": "linux-arm64",
    "arm64": "linux-arm64",
    "armv7l": "linux-arm",
    "armv6l": "linux-arm",
    "i386": "linux-x86",
    "i686": "linux-x86",
    "mips": "linux-mips",
    "mips64": "linux-mips64",
    "ppc64le": "linux-ppc",
    "riscv64": "linux-riscv64",
}

_LUA_REQUIRED = ("zapret-lib.lua", "zapret-antidpi.lua")


def _elf_machine(path: str) -> str | None:
    """Return coarse ELF machine tag or None if not a readable ELF."""
    try:
        with open(path, "rb") as f:
            hdr = f.read(20)
    except OSError:
        return None
    if len(hdr) < 20 or hdr[:4] != b"\x7fELF":
        return None
    ei_data = hdr[5]
    em = hdr[18] | (hdr[19] << 8) if ei_data != 2 else (hdr[18] << 8) | hdr[19]
    return {
        3: "x86",
        40: "arm",
        62: "x86_64",
        183: "aarch64",
    }.get(em, f"em_{em}")


def _host_elf_expected() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x86_64"
    if m in ("aarch64", "arm64"):
        return "aarch64"
    if m in ("armv7l", "armv6l"):
        return "arm"
    if m in ("i386", "i686"):
        return "x86"
    return m


def check_nfqws2_arch(nfq_path: str) -> str | None:
    """Return warning text if ELF arch mismatches host; else None."""
    got = _elf_machine(nfq_path)
    if got is None:
        return None
    expect = _host_elf_expected()
    if got == expect:
        return None
    arch = zapret2_arch() or "linux-x86_64"
    return (
        f"nfqws2 ELF machine={got} but host is {platform.machine()} "
        f"(expected ~{expect}) — Exec format error likely; "
        f"use binaries/{arch}/nfqws2"
    )


@dataclass
class DepsReport:
    ok: bool = True
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    nfqws2: str | None = None
    blobs_dir: str | None = None
    lua_dir: str | None = None
    fetched: bool = False

    def print_report(self) -> None:
        try:
            from colorama import Fore, Style

            y, r, g, reset = Fore.YELLOW, Fore.RED, Fore.GREEN, Style.RESET_ALL
        except Exception:
            y = r = g = reset = ""
        for w in self.warnings:
            print(f"  {y}WARN{reset}: {w}")
        for e in self.errors:
            print(f"  {r}ERROR{reset}: {e}")
        if self.ok and self.nfqws2:
            print(f"  {g}OK{reset}: nfqws2 → {self.nfqws2}")


def fetch_deps_enabled(default: bool = True) -> bool:
    """BLOCKCHECKS_FETCH_DEPS: 1/true on, 0/false off."""
    v = os.environ.get("BLOCKCHECKS_FETCH_DEPS")
    if v is None:
        return default
    return v.strip().lower() not in ("0", "false", "off", "no")


def zapret2_arch(machine: str | None = None) -> str | None:
    """Map host machine to zapret2 ``binaries/<arch>`` folder name."""
    m = (machine or platform.machine() or "").strip().lower()
    return _ARCH_MAP.get(m)


def _http_get(url: str, dest: Path | None = None, timeout: float = 120.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    if dest is not None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    return data


def parse_sha256sum(text: str) -> dict[str, str]:
    """Parse ``sha256sum.txt`` → {filename: hexdigest}."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        digest, name = parts[0], parts[-1]
        name = name.lstrip("*")
        if len(digest) == 64:
            out[os.path.basename(name)] = digest.lower()
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_nfqws2_bin() -> str | None:
    """Resolution order without network fetch."""
    env = os.environ.get("BLOCKCHECKS_NFQWS2", "").strip()
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env

    which = shutil.which("nfqws2")
    if which and os.path.isfile(which):
        return which

    for candidate in (
        "/opt/zapret2/nfq2/nfqws2",
        str(VENDOR_BIN_LINK),
        str(VENDOR_ROOT / "nfq2" / "nfqws2"),
    ):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    arch = zapret2_arch()
    if arch:
        p = VENDOR_ROOT / "binaries" / arch / "nfqws2"
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return None


def _path_ok(path: str | Path) -> bool:
    return bool(path) and os.path.exists(str(path))


def _seed_blobs_from_fake(fake_dir: Path, blobs_dir: Path) -> int:
    """Copy/symlink common fake payloads into blobs_dir. Returns count."""
    blobs_dir.mkdir(parents=True, exist_ok=True)
    if not fake_dir.is_dir():
        return 0
    n = 0
    # Prefer short alias names used by Flowseal/blockcheckS
    mapping = {
        "tls_clienthello_www_google_com.bin": "tls_clienthello_www_google_com.bin",
        "tls_clienthello_max_ru.bin": "tls_clienthello_max_ru.bin",
        "stun.bin": "stun.bin",
        "quic_initial_www_google_com.bin": "quic_initial_www_google_com.bin",
    }
    for src_name, dest_name in mapping.items():
        src = fake_dir / src_name
        if not src.is_file():
            # try any matching file
            continue
        dest = blobs_dir / dest_name
        if dest.exists():
            n += 1
            continue
        try:
            os.symlink(src, dest)
        except OSError:
            shutil.copy2(src, dest)
        n += 1
    # Also link any *.bin from fake into blobs under original names (capped)
    for src in sorted(fake_dir.glob("*.bin"))[:40]:
        dest = blobs_dir / src.name
        if dest.exists():
            continue
        try:
            os.symlink(src, dest)
            n += 1
        except OSError:
            try:
                shutil.copy2(src, dest)
                n += 1
            except OSError:
                pass
    return n


def ensure_zapret2_vendor(*, offline: bool = False) -> tuple[str, str, str]:
    """Download + extract official zapret2 release into DATA_DIR.

    Returns (nfqws2_path, blobs_dir, lua_dir).
    """
    if offline:
        raise RuntimeError("offline: cannot fetch zapret2 (BLOCKCHECKS_FETCH_DEPS / --offline)")

    arch = zapret2_arch()
    if not arch:
        raise RuntimeError(
            f"unsupported CPU arch for prebuilt nfqws2: {platform.machine()!r} "
            f"(supported: {', '.join(sorted(set(_ARCH_MAP.values())))})"
        )

    ensure_dirs()
    DL_CACHE.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "bin").mkdir(parents=True, exist_ok=True)

    print(f"  [deps] fetching zapret2 latest ({arch})…")
    try:
        meta = json.loads(_http_get(GITHUB_API_LATEST).decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        raise RuntimeError(f"GitHub releases API failed: {e}") from e

    tag = meta.get("tag_name") or meta.get("name")
    if not tag:
        raise RuntimeError("GitHub release missing tag_name")
    asset_name = f"zapret2-{tag}.tar.gz"
    sha_name = "sha256sum.txt"

    assets = {a["name"]: a for a in meta.get("assets") or [] if a.get("name")}
    if asset_name not in assets:
        raise RuntimeError(f"release {tag} has no asset {asset_name}")
    tar_url = assets[asset_name]["browser_download_url"]
    sha_url = assets.get(sha_name, {}).get("browser_download_url")

    tar_path = DL_CACHE / asset_name
    if not tar_path.is_file() or tar_path.stat().st_size < 1000:
        print(f"  [deps] downloading {asset_name}…")
        _http_get(tar_url, dest=tar_path)

    if sha_url:
        sha_text = _http_get(sha_url).decode("utf-8", errors="replace")
        digests = parse_sha256sum(sha_text)
        expected = digests.get(asset_name)
        if expected:
            got = sha256_file(tar_path)
            if got != expected:
                tar_path.unlink(missing_ok=True)
                raise RuntimeError(f"sha256 mismatch for {asset_name}: {got} != {expected}")

    # Extract to temp then swap into VENDOR_ROOT
    with tempfile.TemporaryDirectory(prefix="bs_zapret2_", dir=str(DATA_DIR)) as tmp:
        tmp_path = Path(tmp)
        with tarfile.open(tar_path, "r:gz") as tf:
            tf.extractall(tmp_path)  # noqa: S202 — trusted official release after sha256
        # tarball usually has a single top-level directory
        children = [p for p in tmp_path.iterdir() if p.is_dir()]
        extracted = children[0] if len(children) == 1 else tmp_path

        bin_src = extracted / "binaries" / arch / "nfqws2"
        if not bin_src.is_file():
            raise RuntimeError(f"archive missing binaries/{arch}/nfqws2")

        staging = DATA_DIR / f".zapret2-staging-{os.getpid()}"
        if staging.exists():
            shutil.rmtree(staging)
        shutil.copytree(extracted, staging, symlinks=True)

        src_bin = staging / "binaries" / arch / "nfqws2"
        if not src_bin.is_file():
            raise RuntimeError(f"staging missing binaries/{arch}/nfqws2")

        nfq2 = staging / "nfq2"
        nfq2.mkdir(parents=True, exist_ok=True)
        dest_bin = nfq2 / "nfqws2"
        if dest_bin.exists() or dest_bin.is_symlink():
            dest_bin.unlink()
        shutil.copy2(src_bin, dest_bin)
        os.chmod(dest_bin, 0o755)

        blobs_dir = staging / "blobs"
        blobs_dir.mkdir(parents=True, exist_ok=True)
        fake = staging / "files" / "fake"
        _seed_blobs_from_fake(fake, blobs_dir)

        (staging / ".version").write_text(tag + "\n", encoding="utf-8")

        # Atomic replace
        old = DATA_DIR / f".zapret2-old-{os.getpid()}"
        if VENDOR_ROOT.exists():
            if old.exists():
                shutil.rmtree(old)
            VENDOR_ROOT.rename(old)
        staging.rename(VENDOR_ROOT)
        if old.exists():
            shutil.rmtree(old, ignore_errors=True)

    nfqws2 = VENDOR_ROOT / "nfq2" / "nfqws2"
    if not nfqws2.is_file():
        # fallback to binaries path
        nfqws2 = VENDOR_ROOT / "binaries" / arch / "nfqws2"
    os.chmod(nfqws2, 0o755)

    VENDOR_BIN_LINK.parent.mkdir(parents=True, exist_ok=True)
    if VENDOR_BIN_LINK.exists() or VENDOR_BIN_LINK.is_symlink():
        VENDOR_BIN_LINK.unlink()
    try:
        os.symlink(nfqws2, VENDOR_BIN_LINK)
    except OSError:
        shutil.copy2(nfqws2, VENDOR_BIN_LINK)
        os.chmod(VENDOR_BIN_LINK, 0o755)

    lua_dir = VENDOR_ROOT / "lua"
    blobs = VENDOR_ROOT / "blobs"
    fake_dir = VENDOR_ROOT / "files" / "fake"

    cfg.apply_tool_paths(
        nfqws2=str(nfqws2),
        blobs=str(blobs),
        lua_dir=str(lua_dir),
    )
    if fake_dir.is_dir():
        os.environ["BLOCKCHECKS_FAKE_FILES"] = str(fake_dir)

    print(f"  [deps] zapret2 {tag} → {VENDOR_ROOT}")
    return str(nfqws2), str(blobs), str(lua_dir)


def verify_system_dependencies(
    *,
    fetch: bool | None = None,
    offline: bool = False,
    require_linux: bool = True,
) -> DepsReport:
    """Check host tools + nfqws2/lua/blobs; optionally auto-fetch zapret2."""
    report = DepsReport()
    do_fetch = fetch_deps_enabled(True) if fetch is None else fetch

    if require_linux and sys.platform != "linux":
        report.ok = False
        report.errors.append(f"live tests require Linux (got {sys.platform})")
        return report

    # Host tools — warnings only
    if not shutil.which("ip"):
        report.warnings.append("`ip` not in PATH (needed for netns)")
    if not (shutil.which("iptables") or shutil.which("iptables-nft")):
        report.warnings.append("`iptables` / `iptables-nft` not in PATH")
    if not shutil.which("sudo"):
        report.warnings.append("`sudo` not in PATH")
    else:
        # Non-fatal probe
        import subprocess

        r = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            report.warnings.append(
                "passwordless sudo (`sudo -n`) unavailable — live runs may prompt"
            )

    nfq = resolve_nfqws2_bin()
    if not nfq and do_fetch and not offline:
        try:
            nfq, blobs, lua = ensure_zapret2_vendor(offline=False)
            report.fetched = True
            report.nfqws2 = nfq
            report.blobs_dir = blobs
            report.lua_dir = lua
        except Exception as e:
            report.ok = False
            report.errors.append(f"nfqws2 auto-fetch failed: {e}")
            report.errors.append(
                "Install zapret2 manually to /opt/zapret2 or set BLOCKCHECKS_NFQWS2, "
                "or re-run without --offline / with network"
            )
            return report
    elif not nfq:
        report.ok = False
        report.errors.append(
            "nfqws2 not found (PATH, /opt/zapret2/nfq2/nfqws2, "
            f"{VENDOR_BIN_LINK}). Set BLOCKCHECKS_NFQWS2 or allow fetch "
            "(default; disable with --no-fetch-deps / BLOCKCHECKS_FETCH_DEPS=0)"
        )
        return report
    else:
        report.nfqws2 = nfq
        # Align module paths if pointing at vendor tree
        if str(VENDOR_ROOT) in nfq or nfq == str(VENDOR_BIN_LINK):
            lua = VENDOR_ROOT / "lua"
            blobs = VENDOR_ROOT / "blobs"
            if lua.is_dir() and blobs.is_dir():
                cfg.apply_tool_paths(nfqws2=nfq, blobs=str(blobs), lua_dir=str(lua))
                report.blobs_dir = str(blobs)
                report.lua_dir = str(lua)
        else:
            cfg.apply_tool_paths(nfqws2=nfq)

    arch_msg = check_nfqws2_arch(nfq) if nfq else None
    if arch_msg:
        report.ok = False
        report.errors.append(arch_msg)

    # Lua
    lua_dir = os.environ.get("BLOCKCHECKS_LUA_DIR") or cfg.LUA_INIT_DIR
    report.lua_dir = lua_dir
    missing_lua = [n for n in _LUA_REQUIRED if not _path_ok(Path(lua_dir) / n)]
    if missing_lua:
        if do_fetch and not offline and not report.fetched:
            try:
                nfq, blobs, lua = ensure_zapret2_vendor(offline=False)
                report.fetched = True
                report.nfqws2 = nfq
                report.blobs_dir = blobs
                report.lua_dir = lua
                missing_lua = [n for n in _LUA_REQUIRED if not _path_ok(Path(lua) / n)]
            except Exception as e:
                report.warnings.append(f"lua missing {missing_lua}; fetch failed: {e}")
        if missing_lua:
            report.warnings.append(f"lua scripts missing under {lua_dir}: {', '.join(missing_lua)}")

    # Blobs
    blobs_dir = os.environ.get("BLOCKCHECKS_BLOBS") or cfg.BLOB_DIR
    report.blobs_dir = blobs_dir
    if not os.path.isdir(blobs_dir):
        report.warnings.append(
            f"blobs dir missing: {blobs_dir} (repo ships blobs/; see docs/cookbook/blobs.md)"
        )
    else:
        n_bin = sum(1 for _ in Path(blobs_dir).glob("*.bin"))
        if n_bin == 0:
            report.warnings.append(
                f"no .bin blobs in {blobs_dir} — strategies with blob= may fail "
                "(docs/cookbook/blobs.md; optional scripts/install_blobs.sh)"
            )

    return report
