#!/usr/bin/env python3
import os
import subprocess
import tempfile
import time
from pathlib import Path

from blockchecks.engine.config import NFQWS2_BIN, LUA_INIT_SCRIPTS, BLOB_DIR
from blockchecks.engine.firewall import Firewall

qnum = 219
log = Path("logs/manual_fw_start.log")
log.parent.mkdir(exist_ok=True)
if log.exists():
    log.unlink()

lines = [
    f"--qnum={qnum}",
    "--filter-tcp=443",
    "--filter-l3=ipv4",
    "--filter-l7=tls",
    "--ipcache-lifetime=0",
    "--bind-fix4",
    f"--debug=@{log}",
    "--payload=tls_client_hello",
    f"--blob=stun:@{BLOB_DIR}/stun.bin",
    "--lua-desync=fake:blob=stun:repeats=6:tcp_ts=-1000",
]
for lua in LUA_INIT_SCRIPTS:
    if os.path.exists(lua):
        lines.append(f"--lua-init=@{lua}")

fd, conf = tempfile.mkstemp(suffix=".conf")
os.close(fd)
Path(conf).write_text("\n".join(lines) + "\n")
os.chmod(conf, 0o644)

fw = Firewall()
fw.prepare_tcp(qnum=qnum)
print("iptables ready, launching", NFQWS2_BIN, conf)
proc = subprocess.Popen(
    ["sudo", "-n", NFQWS2_BIN, f"@{conf}"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    start_new_session=True,
)
time.sleep(1.5)
print("poll", proc.poll())
if proc.poll() is not None:
    o, e = proc.communicate()
    print("STDOUT:\n", o.decode(errors="replace")[-1500:])
    print("STDERR:\n", e.decode(errors="replace")[-1500:])
else:
    print("ALIVE")
    try:
        os.killpg(proc.pid, 9)
    except ProcessLookupError:
        pass
print("DEBUG LOG:\n", log.read_text(errors="replace") if log.exists() else "missing")
fw.cleanup()
os.unlink(conf)
