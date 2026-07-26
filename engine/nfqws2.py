"""nfqws2 process manager — start, stop, load config files."""

import os
import subprocess
import time
from pathlib import Path
from typing import Optional

NFQWS2_BIN = "/opt/zapret2/nfq2/nfqws2"
LUA_INIT = [
    "/opt/zapret2/lua/zapret-lib.lua",
    "/opt/zapret2/lua/zapret-antidpi.lua",
]


class Nfqws2Manager:
    """Manages nfqws2 daemon lifecycle.

    start():        build config from strategy string + options
    start_config(): use pre-built .conf file directly
    Phase 2:        reconfigure without restart via SIGHUP or config file.
    """

    def __init__(self, ns_name: Optional[str] = None):
        self.ns_name = ns_name
        self._proc: Optional[subprocess.Popen] = None
        self._qnum = 200

    def _launch(self, config_arg: str) -> None:
        """Launch nfqws2 with @config_arg and verify it's running."""
        if self.ns_name:
            cmd = ["sudo", "ip", "netns", "exec", self.ns_name,
                   NFQWS2_BIN, config_arg, "--daemon"]
        else:
            cmd = ["sudo", NFQWS2_BIN, config_arg, "--daemon"]

        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )
        time.sleep(1.0)

        check_cmd = ["pgrep", "-x", "nfqws2"]
        if self.ns_name:
            check_cmd = (
                ["sudo", "ip", "netns", "exec", self.ns_name] + check_cmd
            )

        r = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            stderr = ""
            try:
                self._proc.wait(timeout=1)
                stderr = (
                    self._proc.stderr.read().decode()
                    if self._proc.stderr else ""
                )
            except Exception:
                pass
            raise RuntimeError(f"nfqws2 failed to start: {stderr[:300]}")

    def start_config(self, config_path: str) -> None:
        """Start nfqws2 using a pre-built .conf file.

        The config file should contain all --qnum, --filter-*, --lua-init,
        --blob, --hostlist, --lua-desync lines (same format as keenetic .conf).
        """
        abspath = Path(config_path).resolve()
        if not abspath.exists():
            raise FileNotFoundError(f"Config not found: {abspath}")
        self._launch(f"@{abspath}")

    def start(self, strategy: str, hostlist: Optional[list[str]] = None,
              qnum: int = 200, filter_tcp: str = "443",
              blobs: Optional[list[str]] = None,
              extra_lua_desync: Optional[list[str]] = None) -> None:
        """Start nfqws2 daemon with given strategy (backward compat).

        blobs: list of blob names to load (e.g. ['stun', 'max_ru'])
          -- loaded from /opt/zapret2/blobs/<name>.bin
        extra_lua_desync: additional --lua-desync lines (e.g. for multi-strategy)
        """
        self._qnum = qnum
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

        if blobs:
            for blob_name in blobs:
                blob_path = f"/opt/zapret2/blobs/{blob_name}.bin"
                if os.path.exists(blob_path):
                    lines.append(f"--blob={blob_name}:@{blob_path}")

        if hostlist:
            hostlist_path = f"/tmp/bs_hostlist_{os.getpid()}.txt"
            with open(hostlist_path, "w") as f:
                for d in hostlist:
                    f.write(f"{d}\n")
            lines.append(f"--hostlist={hostlist_path}")

        lines.append("--payload=tls_client_hello")
        lines.append(f"--lua-desync={strategy}")
        if extra_lua_desync:
            for extra in extra_lua_desync:
                lines.append(f"--lua-desync={extra}")

        config_path = f"/tmp/bs_nfqws2_{os.getpid()}.conf"
        with open(config_path, "w") as f:
            f.write("\n".join(lines))
        self._launch(f"@{config_path}")

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
