#!/usr/bin/env python3
import os
import time

os.environ["BLOCKCHECKS_NFQWS2_DEBUG"] = "1"

from blockchecks.engine.firewall import Firewall
from blockchecks.engine.nfqws2 import Nfqws2Manager

strategy = "fake:blob=stun:repeats=6:tcp_ts=-1000"
qnum = 219

fw = Firewall()
mgr = Nfqws2Manager()
try:
    print("prepare_tcp…")
    fw.prepare_tcp(qnum=qnum)
    print("start…")
    mgr.start(strategy, hostlist=["discord.com"], qnum=qnum)
    print("OK pid", mgr._pid, "debug", mgr.last_debug_log)
    time.sleep(1.0)
    print("still alive", mgr._proc.poll() if mgr._proc else None)
except Exception as e:
    print("FAIL", e)
    if mgr.last_debug_log and os.path.exists(mgr.last_debug_log):
        print("--- debug ---")
        print(open(mgr.last_debug_log, errors="replace").read())
finally:
    mgr.stop()
    fw.cleanup()
    print("cleaned")
