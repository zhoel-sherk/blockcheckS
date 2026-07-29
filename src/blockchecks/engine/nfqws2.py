"""nfqws2 process manager — start, stop, load config files.

Uses foreground subprocess with start_new_session for clean killpg.
No --daemon, no pkill -9 — only kills owned process groups via PID.
"""

import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from blockchecks.engine.config import NFQWS2_BIN, LUA_INIT_SCRIPTS


class Nfqws2Manager:
    """Manages a single nfqws2 process via foreground Popen + killpg."""

    def __init__(self, ns_name: Optional[str] = None, qnum: int = 200):
        self.ns_name = ns_name
        self._qnum = qnum
        self._proc: Optional[subprocess.Popen] = None
        self._pid: Optional[int] = None
        self._temp_files: list[str] = []

    def _launch(self, config_arg: str, *, stop_first: bool = True) -> None:
        """Start nfqws2 in foreground, verify it's alive.

        stop_first=True clears any prior process/temps. Callers that just
        created a temp config and appended it to ``_temp_files`` must pass
        stop_first=False (and call ``stop()`` themselves beforehand),
        otherwise ``stop()`` deletes the config before nfqws2 can read it.
        """
        if stop_first:
            self.stop()

        args = [NFQWS2_BIN, config_arg]
        if self.ns_name:
            args = ["sudo", "-n", "ip", "netns", "exec", self.ns_name] + args
        else:
            args = ["sudo", "-n"] + args

        self._proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self._pid = self._proc.pid
        time.sleep(0.8)

        if self._proc.poll() is not None:
            self._proc = None
            self._pid = None
            raise RuntimeError("nfqws2 failed to start (exited immediately)")

    def start_config(self, config_path: str) -> None:
        """Start nfqws2 using a pre-built .conf file."""
        abspath = Path(config_path).resolve()
        if not abspath.exists():
            raise FileNotFoundError(f"Config not found: {abspath}")
        self._launch(f"@{abspath}")

    def start(self, strategy: str, hostlist: Optional[list[str]] = None,
              qnum: int = 200, filter_tcp: str = "443",
              blobs: Optional[list[str]] = None,
              extra_lua_desync: Optional[list[str]] = None) -> None:
        """Start nfqws2 with inline strategy (backward compat)."""
        self.stop()  # clear prior proc/temps before creating a new conf
        self._qnum = qnum
        lines = [
            f"--qnum={qnum}",
            f"--filter-tcp={filter_tcp}",
            "--filter-l3=ipv4",
            "--filter-l7=tls",
            "--ipcache-lifetime=0",
            "--bind-fix4",
        ]
        for lua in LUA_INIT_SCRIPTS:
            if os.path.exists(lua):
                lines.append(f"--lua-init=@{lua}")

        if blobs:
            for blob_name in blobs:
                blob_path = f"/opt/zapret2/blobs/{blob_name}.bin"
                if os.path.exists(blob_path):
                    lines.append(f"--blob={blob_name}:@{blob_path}")

        if hostlist:
            fd, hostlist_path = tempfile.mkstemp(prefix="bs_hostlist_", suffix=".txt")
            try:
                with os.fdopen(fd, "w") as f:
                    for d in hostlist:
                        f.write(f"{d}\n")
                lines.append(f"--hostlist={hostlist_path}")
                self._temp_files.append(hostlist_path)
            except Exception:
                try:
                    os.unlink(hostlist_path)
                except OSError:
                    pass
                raise

        lines.append("--payload=tls_client_hello")
        lines.append(f"--lua-desync={strategy}")
        if extra_lua_desync:
            for extra in extra_lua_desync:
                lines.append(f"--lua-desync={extra}")

        fd, config_path = tempfile.mkstemp(prefix="bs_nfqws2_", suffix=".conf")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(lines))
            os.chmod(config_path, 0o644)
            self._temp_files.append(config_path)
            self._launch(f"@{config_path}", stop_first=False)
        except Exception:
            try:
                os.unlink(config_path)
            except OSError:
                pass
            if config_path in self._temp_files:
                self._temp_files.remove(config_path)
            raise

    def stop(self) -> None:
        """Kill the owned nfqws2 process group via killpg; unlink temp files."""
        if self._pid is not None:
            try:
                os.killpg(os.getpgid(self._pid), signal.SIGTERM)
                time.sleep(0.3)
                try:
                    os.killpg(os.getpgid(self._pid), signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
            except (ProcessLookupError, OSError):
                pass
            self._pid = None

        if self._proc is not None:
            try:
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                    self._proc.wait(timeout=2)
                except Exception:
                    pass
            self._proc = None

        for path in self._temp_files:
            try:
                os.unlink(path)
            except OSError:
                pass
        self._temp_files.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stop()
