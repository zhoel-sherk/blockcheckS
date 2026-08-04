"""nfqws2 process manager — start, stop, load config files.

Two launch modes:

- ``start_daemon`` — ``@config`` + ``--daemon`` inside temp conf (async/pair coexist).
- ``Nfqws2Manager`` — foreground Popen + killpg (sync test_runner / voice bootstrap).
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from blockchecks.engine.config import (
    BLOB_DIR,
    get_lua_init_scripts,
    get_nfqws2_bin,
    nfqws2_debug_conf_line,
)
from blockchecks.engine.nfqws2_settle import wait_nfqws2_ready


def inject_debug_and_daemon(config_path: str, tag: str = "") -> str | None:
    """Ensure conf contains --daemon and optional --debug=@log. Returns log path."""
    try:
        with open(config_path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return None
    lines = [ln for ln in text.splitlines() if ln.strip()]
    changed = False
    if not any(ln.startswith("--daemon") for ln in lines):
        lines.insert(0, "--daemon")
        changed = True
    dbg, dbg_path = nfqws2_debug_conf_line(tag=tag or "async")
    if dbg and not any(ln.startswith("--debug=") for ln in lines):
        lines.insert(1 if lines and lines[0].startswith("--daemon") else 0, dbg)
        changed = True
        if dbg_path:
            print(f"  [nfqws2 debug] {dbg_path}")
    if changed:
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except OSError:
            return None
    return dbg_path if dbg else None


def start_daemon(
    ns_name: str,
    config_path: str,
    kill_existing: bool = True,
    *,
    settle_max: float | None = None,
    settle_poll: float | None = None,
) -> float:
    """Launch nfqws2 in daemon mode inside ns. Non-blocking.

    kill_existing=True (default) clears prior nfqws2 in the ns — for solo
    TCP/UDP checks. Pair matrix must pass kill_existing=False when starting
    the UDP instance so the TCP desync (qnum 200) stays alive.

    Note: with ``@config`` nfqws2 ignores trailing CLI flags — put ``--debug``
    and ``--daemon`` inside a *temporary* copy of the config.

    Returns settle elapsed seconds (B1 readiness poll).
    """
    _fd, tmp_conf = tempfile.mkstemp(prefix="bs_nfq_", suffix=".conf")
    os.close(_fd)
    try:
        shutil.copy2(config_path, tmp_conf)
        inject_debug_and_daemon(tmp_conf, tag=ns_name)
        if kill_existing:
            subprocess.run(
                ["sudo", "ip", "netns", "exec", ns_name, "pkill", "-9", "nfqws2"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        # @config must be the only argument; daemon/debug are inside the file
        cmd = [
            "sudo",
            "ip",
            "netns",
            "exec",
            ns_name,
            get_nfqws2_bin(),
            f"@{tmp_conf}",
        ]
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return wait_nfqws2_ready(ns_name, max_wait=settle_max, poll_interval=settle_poll)
    finally:
        # Daemon has read @config into memory by settle; do not leak /tmp/bs_nfq_*
        try:
            os.unlink(tmp_conf)
        except OSError:
            pass


class Nfqws2Manager:
    """Manages a single nfqws2 process via foreground Popen + killpg."""

    def __init__(self, ns_name: str | None = None, qnum: int = 200):
        self.ns_name = ns_name
        self._qnum = qnum
        self._proc: subprocess.Popen | None = None
        self._pid: int | None = None
        self._temp_files: list[str] = []
        self.last_debug_log: str | None = None

    def _launch(self, config_arg: str, *, stop_first: bool = True) -> None:
        """Start nfqws2 in foreground, verify it's alive.

        stop_first=True clears any prior process/temps. Callers that just
        created a temp config and appended it to ``_temp_files`` must pass
        stop_first=False (and call ``stop()`` themselves beforehand),
        otherwise ``stop()`` deletes the config before nfqws2 can read it.
        """
        if stop_first:
            self.stop()

        args = [get_nfqws2_bin(), config_arg]
        if self.ns_name:
            args = ["sudo", "-n", "ip", "netns", "exec", self.ns_name] + args
        else:
            args = ["sudo", "-n"] + args

        self._proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            # Never PIPE: unread buffer blocks a chatty/debug nfqws2.
            # Init/errors go to --debug=@logfile when enabled.
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self._pid = self._proc.pid
        if self.ns_name:
            wait_nfqws2_ready(self.ns_name)
        else:
            time.sleep(0.2)

        if self._proc.poll() is not None:
            hint = ""
            if self.last_debug_log and os.path.exists(self.last_debug_log):
                try:
                    tail = Path(self.last_debug_log).read_text(errors="replace")[-300:]
                    hint = f"; debug_tail={tail!r}"
                except OSError:
                    pass
            self._proc = None
            self._pid = None
            raise RuntimeError("nfqws2 failed to start (exited immediately)" + hint)

    def start_config(self, config_path: str) -> None:
        """Start nfqws2 using a pre-built .conf file."""
        abspath = Path(config_path).resolve()
        if not abspath.exists():
            raise FileNotFoundError(f"Config not found: {abspath}")
        self._launch(f"@{abspath}")

    def start(
        self,
        strategy: str,
        hostlist: list[str] | None = None,
        qnum: int = 200,
        filter_tcp: str = "443",
        blobs: list[str] | None = None,
        extra_lua_desync: list[str] | None = None,
    ) -> None:
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
        dbg, dbg_path = nfqws2_debug_conf_line(tag=f"q{qnum}")
        if dbg:
            lines.append(dbg)
            self.last_debug_log = dbg_path
            if dbg_path:
                print(f"  [nfqws2 debug] {dbg_path}")
        for lua in get_lua_init_scripts():
            if os.path.exists(lua):
                lines.append(f"--lua-init=@{lua}")

        # Explicit blobs= plus auto-discover blob=/seqovl_pattern= from strategy
        from blockchecks.engine.blob_aliases import append_blob_cli_lines, extract_blob_names

        blob_names: list[str] = list(blobs or [])
        for name in extract_blob_names(strategy):
            if name not in blob_names:
                blob_names.append(name)
        append_blob_cli_lines(lines, blob_names, BLOB_DIR)

        if hostlist:
            fd, hostlist_path = tempfile.mkstemp(prefix="bs_hostlist_", suffix=".txt")
            try:
                with os.fdopen(fd, "w") as f:
                    for d in hostlist:
                        f.write(f"{d}\n")
                # nfqws2 drops UID after init and re-opens hostlist — must be world-readable
                os.chmod(hostlist_path, 0o644)
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
                time.sleep(0.1)
                try:
                    os.killpg(os.getpgid(self._pid), signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
            except (ProcessLookupError, OSError):
                pass
            self._pid = None

        if self._proc is not None:
            try:
                self._proc.wait(timeout=1)
            except Exception:
                try:
                    self._proc.kill()
                    self._proc.wait(timeout=1)
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
