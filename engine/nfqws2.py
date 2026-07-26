"""nfqws2 process manager — start, stop, reconfigure (MVP: restart per strategy)."""

import os
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

NFQWS2_BIN = "/opt/zapret2/nfq2/nfqws2"
LUA_INIT = [
    "/opt/zapret2/lua/zapret-lib.lua",
    "/opt/zapret2/lua/zapret-antidpi.lua",
]


@dataclass
class Nfqws2Config:
    qnum: int = 200
    filter_tcp: str = "443"
    filter_l3: str = "ipv4"
    filter_l7: str = "tls"
    hostlist_domains: Optional[list[str]] = None
    ipcache_lifetime: int = 0
    bind_fix4: bool = True
    payload: str = "tls_client_hello"
    lua_desync: str = ""  # the strategy string (e.g. "fake:repeats=6:tcp_ts=-1000")


class Nfqws2Manager:
    """Manages nfqws2 daemon lifecycle.

    Phase 1 (MVP): start/stop per strategy — no reuse.
    Phase 2: reconfigure without restart via SIGHUP or config file.
    """

    def __init__(self, ns_name: Optional[str] = None):
        self.ns_name = ns_name
        self._proc: Optional[subprocess.Popen] = None
        self._qnum = 200

    def _cmd(self, *args: str) -> list[str]:
        """Build command with optional ip netns exec prefix."""
        cmd = [NFQWS2_BIN]
        if self.ns_name:
            cmd = ["sudo", "ip", "netns", "exec", self.ns_name, NFQWS2_BIN]
        cmd.extend(args)
        return cmd

    def start(self, strategy: str, hostlist: Optional[list[str]] = None,
              qnum: int = 200, filter_tcp: str = "443") -> None:
        """Start nfqws2 daemon with given strategy."""
        self._qnum = qnum

        # Build config file
        lines = [
            f"--qnum={qnum}",
            f"--filter-tcp={filter_tcp}",
            "--filter-l3=ipv4",
            "--filter-l7=tls",
            "--ipcache-lifetime=0",
            "--bind-fix4",
        ]
        for lua in LUA_INIT:
            if os.path.exists(lua):
                lines.append(f"--lua-init=@{lua}")

        if hostlist:
            hostlist_path = f"/tmp/bs_hostlist_{os.getpid()}.txt"
            with open(hostlist_path, "w") as f:
                for d in hostlist:
                    f.write(f"{d}\n")
            lines.append(f"--hostlist={hostlist_path}")

        lines.append(f"--payload=tls_client_hello")
        lines.append(f"--lua-desync={strategy}")

        # Write config (--daemon is passed on CLI, not in config file)
        config_path = f"/tmp/bs_nfqws2_{os.getpid()}.conf"
        with open(config_path, "w") as f:
            f.write("\n".join(lines))

        # Launch
        config_arg = f"@{config_path}"
        if self.ns_name:
            cmd = ["sudo", "ip", "netns", "exec", self.ns_name,
                   NFQWS2_BIN, config_arg, "--daemon"]
        else:
            cmd = ["sudo", NFQWS2_BIN, config_arg, "--daemon"]

        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE)
        time.sleep(0.8)

        # Verify running
        check_cmd = ["pgrep", "-x", "nfqws2"]
        if self.ns_name:
            check_cmd = ["sudo", "ip", "netns", "exec", self.ns_name] + check_cmd
        else:
            check_cmd = ["pgrep", "-x", "nfqws2"]

        r = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            stderr = ""
            try:
                self._proc.wait(timeout=1)
                stderr = self._proc.stderr.read().decode() if self._proc.stderr else ""
            except Exception:
                pass
            raise RuntimeError(f"nfqws2 failed to start: {stderr[:300]}")

    def stop(self) -> None:
        """Kill nfqws2 daemon."""
        if self._proc:
            kill_cmd = ["sudo", "pkill", "-9", "nfqws2"]
            if self.ns_name:
                kill_cmd = ["sudo", "ip", "netns", "exec", self.ns_name,
                            "pkill", "-9", "nfqws2"]
            subprocess.run(kill_cmd, capture_output=True, timeout=5)
            try:
                self._proc.wait(timeout=3)
            except Exception:
                pass
            self._proc = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stop()
