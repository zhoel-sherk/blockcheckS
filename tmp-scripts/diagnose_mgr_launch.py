#!/usr/bin/env python3
import os
import subprocess
import time

os.environ["BLOCKCHECKS_NFQWS2_DEBUG"] = "1"

from blockchecks.engine.firewall import Firewall
from blockchecks.engine.nfqws2 import Nfqws2Manager

# Monkeypatch _launch to keep conf and show argv + poll timing
orig = Nfqws2Manager._launch

def _launch(self, config_arg, *, stop_first=True):
    if stop_first:
        self.stop()
    conf = config_arg[1:] if config_arg.startswith("@") else config_arg
    print("CONF PATH", conf)
    print("CONF CONTENT:\n", open(conf).read())
    args = ["sudo", "-n", __import__("blockchecks.engine.config", fromlist=["NFQWS2_BIN"]).NFQWS2_BIN, config_arg]
    print("ARGV", args)
    self._proc = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    )
    self._pid = self._proc.pid
    for i in range(10):
        time.sleep(0.2)
        p = self._proc.poll()
        print(f"t={0.2*(i+1):.1f} poll={p}")
        if p is not None:
            o, e = self._proc.communicate()
            print("STDOUT", o.decode(errors="replace")[-1500:])
            print("STDERR", e.decode(errors="replace")[-1500:])
            self._proc = None
            self._pid = None
            raise RuntimeError("exited")
    print("ALIVE")

Nfqws2Manager._launch = _launch

fw = Firewall()
mgr = Nfqws2Manager()
try:
    fw.prepare_tcp(qnum=219)
    mgr.start(
        "fake:blob=stun:repeats=6:tcp_ts=-1000",
        hostlist=["discord.com"],
        qnum=219,
    )
finally:
    try:
        mgr.stop()
    except Exception:
        pass
    fw.cleanup()
