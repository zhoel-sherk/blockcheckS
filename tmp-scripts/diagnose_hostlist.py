#!/usr/bin/env python3
import os
import subprocess
import tempfile
import time
from pathlib import Path

from blockchecks.engine.config import NFQWS2_BIN, LUA_INIT_SCRIPTS, BLOB_DIR
from blockchecks.engine.firewall import Firewall

qnum = 219
log = Path("logs/manual_hostlist.log")
log.parent.mkdir(exist_ok=True)
if log.exists():
    log.unlink()

fdh, hostlist = tempfile.mkstemp(prefix="bs_hostlist_", suffix=".txt")
os.write(fdh, b"discord.com\n")
os.close(fdh)
os.chmod(hostlist, 0o644)

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
    f"--hostlist={hostlist}",
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
proc = subprocess.Popen(
    ["sudo", "-n", NFQWS2_BIN, f"@{conf}"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    start_new_session=True,
)
for i in range(10):
    time.sleep(0.2)
    p = proc.poll()
    print(f"t={0.2*(i+1):.1f}s poll={p}")
    if p is not None:
        o, e = proc.communicate()
        print("STDOUT:", o.decode(errors="replace")[-1200:])
        print("STDERR:", e.decode(errors="replace")[-1200:])
        break
else:
    print("ALIVE after 2s")
    try:
        os.killpg(proc.pid, 9)
    except ProcessLookupError:
        pass

print("LOG:\n", log.read_text(errors="replace") if log.exists() else "missing")
fw.cleanup()
os.unlink(conf)
os.unlink(hostlist)
