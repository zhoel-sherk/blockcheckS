#!/usr/bin/env python3
import os
import subprocess
import tempfile
import time
from pathlib import Path

NFQWS2 = "/opt/zapret2/nfq2/nfqws2"
strategy = "hostfakesplit:nofake2:tcp_md5:repeats=1"
log = Path("logs/probe_hs_stderr.log")
log.parent.mkdir(exist_ok=True)
if log.exists():
    log.unlink()
lines = [
    "--qnum=219",
    "--filter-tcp=443",
    "--filter-l3=ipv4",
    "--filter-l7=tls",
    "--ipcache-lifetime=0",
    "--bind-fix4",
    "--payload=tls_client_hello",
    f"--debug=@{log}",
    "--lua-init=@/opt/zapret2/lua/zapret-lib.lua",
    "--lua-init=@/opt/zapret2/lua/zapret-antidpi.lua",
    f"--lua-desync={strategy}",
]
fd, conf = tempfile.mkstemp(suffix=".conf")
os.close(fd)
Path(conf).write_text("\n".join(lines) + "\n")
os.chmod(conf, 0o644)
subprocess.run(
    [
        "sudo", "-n", "iptables", "-I", "OUTPUT", "1",
        "-p", "tcp", "--dport", "443", "-j", "NFQUEUE",
        "--queue-num", "219", "--queue-bypass",
    ],
    check=False,
)
proc = subprocess.Popen(
    ["sudo", "-n", NFQWS2, f"@{conf}"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    start_new_session=True,
)
time.sleep(1.2)
print("poll", proc.poll())
if proc.poll() is not None:
    o, e = proc.communicate()
    print("OUT", o.decode(errors="replace")[-800:])
    print("ERR", e.decode(errors="replace")[-800:])
else:
    print("ALIVE")
    r = subprocess.run(
        [
            ".venv/bin/python",
            "-c",
            "import curl_cffi; r=curl_cffi.get('https://discord.com', impersonate='chrome124', http_version=2, timeout=4, allow_redirects=False); print(r.status_code, len(r.content))",
        ],
        capture_output=True,
        text=True,
    )
    print("CURL", r.stdout.strip(), r.stderr.strip()[:200])
    time.sleep(0.3)
    try:
        os.killpg(proc.pid, 9)
    except ProcessLookupError:
        pass
print("LOG_BYTES", log.stat().st_size if log.exists() else 0)
if log.exists():
    print(log.read_text(errors="replace")[-1000:])
subprocess.run(
    [
        "sudo", "-n", "iptables", "-D", "OUTPUT",
        "-p", "tcp", "--dport", "443", "-j", "NFQUEUE",
        "--queue-num", "219", "--queue-bypass",
    ],
    check=False,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
os.unlink(conf)
