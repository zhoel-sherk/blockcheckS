#!/usr/bin/env python3
"""Probe nfqws2 strategy execution with --debug=@logfile (no full scan)."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

NFQWS2 = os.environ.get("BLOCKCHECKS_NFQWS2", "/opt/zapret2/nfq2/nfqws2")
BLOB_DIR = "/opt/zapret2/blobs"
LUA = [
    "/opt/zapret2/lua/zapret-lib.lua",
    "/opt/zapret2/lua/zapret-antidpi.lua",
]
STRATEGIES = [
    "fake:blob=stun:repeats=6:tcp_ts=-1000",
    "hostfakesplit:nofake2:tcp_md5:repeats=1",
    "fake:blob=max_ru:repeats=6:tcp_ts=-1000",
]
DOMAIN = os.environ.get("BS_PROBE_DOMAIN", "discord.com")
LOG_DIR = Path(os.environ.get("BS_PROBE_LOGDIR", "logs"))
QNUM = 219


def build_conf(strategy: str, debug_log: Path) -> Path:
    lines = [
        f"--qnum={QNUM}",
        "--filter-tcp=443",
        "--filter-l3=ipv4",
        "--filter-l7=tls",
        "--ipcache-lifetime=0",
        "--bind-fix4",
        "--payload=tls_client_hello",
        f"--debug=@{debug_log}",
    ]
    for lua in LUA:
        if os.path.exists(lua):
            lines.append(f"--lua-init=@{lua}")
    for m in re.finditer(r"blob=(\w+)", strategy):
        name = m.group(1)
        cand = sorted(
            f
            for f in os.listdir(BLOB_DIR)
            if name in f and f.endswith(".bin") and "quic_initial" not in f
        )
        if not cand:
            cand = sorted(f for f in os.listdir(BLOB_DIR) if name in f and f.endswith(".bin"))
        if cand:
            lines.append(f"--blob={name}:@{BLOB_DIR}/{cand[0]}")
    lines.append(f"--lua-desync={strategy}")
    fd, path = tempfile.mkstemp(prefix="bs_probe_", suffix=".conf")
    os.close(fd)
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(path, 0o644)
    return Path(path)


def run_one(strategy: str) -> dict:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", strategy)[:50]
    debug_log = LOG_DIR / f"probe_{safe}.log"
    if debug_log.exists():
        debug_log.unlink()
    conf = build_conf(strategy, debug_log)

    # iptables + nfqws2
    subprocess.run(
        [
            "sudo",
            "-n",
            "iptables",
            "-I",
            "OUTPUT",
            "1",
            "-p",
            "tcp",
            "--dport",
            "443",
            "-j",
            "NFQUEUE",
            "--queue-num",
            str(QNUM),
            "--queue-bypass",
        ],
        check=False,
    )
    proc = subprocess.Popen(
        ["sudo", "-n", NFQWS2, f"@{conf}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    time.sleep(1.0)
    alive = proc.poll() is None
    curl = subprocess.run(
        [
            "sudo",
            "-n",
            os.environ.get(
                "BLOCKCHECKS_PYTHON",
                "/home/zhoel/workspace/blockcheckS/.venv/bin/python",
            ),
            "-c",
            (
                "import curl_cffi,sys\n"
                f"r=curl_cffi.get('https://{DOMAIN}', impersonate='chrome124', "
                "http_version=2, timeout=4, allow_redirects=False)\n"
                "print(r.status_code, len(r.content))\n"
            ),
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    # cleanup
    try:
        os.killpg(proc.pid, 9)
    except ProcessLookupError:
        pass
    subprocess.run(
        [
            "sudo",
            "-n",
            "iptables",
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "443",
            "-j",
            "NFQUEUE",
            "--queue-num",
            str(QNUM),
            "--queue-bypass",
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        conf.unlink()
    except OSError:
        pass

    log_text = debug_log.read_text(encoding="utf-8", errors="replace") if debug_log.exists() else ""
    checks = {
        "nfqws2_alive": alive,
        "debug_log_bytes": len(log_text),
        "has_payload_tls": "tls_client_hello" in log_text or "payload" in log_text.lower(),
        "has_lua_desync": "lua-desync" in log_text or "desync" in log_text.lower(),
        "has_blob" if "blob=" in strategy else "blob_n/a": (
            "blob" in log_text.lower() if "blob=" in strategy else True
        ),
        "has_queue_bind": "queue" in log_text.lower() or "nfq" in log_text.lower(),
        "curl_out": (curl.stdout or curl.stderr or "")[:120].strip(),
        "curl_rc": curl.returncode,
        "log_path": str(debug_log),
        "log_tail": "\n".join(log_text.splitlines()[-25:]),
    }
    return checks


def main():
    print(f"=== strategy probe domain={DOMAIN} qnum={QNUM} ===")
    for s in STRATEGIES:
        print(f"\n--- {s} ---")
        try:
            r = run_one(s)
        except Exception as e:
            print("FAIL", type(e).__name__, e)
            continue
        for k, v in r.items():
            if k == "log_tail":
                continue
            print(f"  {k}: {v}")
        print("  log_tail:")
        for line in (r.get("log_tail") or "").splitlines():
            print(f"    {line}")


if __name__ == "__main__":
    main()
