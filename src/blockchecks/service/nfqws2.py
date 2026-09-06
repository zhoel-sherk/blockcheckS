"""Start and stop nfqws2: daemon @config, or foreground Popen plus PID-scope kill."""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from pathlib import Path

from blockchecks.engine.config import (
    BLOB_DIR,
    get_lua_init_scripts,
    nfqws2_debug_conf_line,
)
from blockchecks.service.nfqws2_launcher import (
    NFQWS2_BIND_ATTEMPTS,
    Nfqws2Launcher,
    _daemon_popens,
    _reap_daemon_popens,
    _reclaim_debug_log,
    inject_debug_and_daemon,
    open_out_capture,
    start_daemon,
)

log = logging.getLogger(__name__)

__all__ = [
    "NFQWS2_BIND_ATTEMPTS",
    "Nfqws2Manager",
    "Nfqws2Launcher",
    "_daemon_popens",
    "_reap_daemon_popens",
    "_reclaim_debug_log",
    "inject_debug_and_daemon",
    "open_out_capture",
    "start_daemon",
]


class Nfqws2Manager:
    """Manages a single nfqws2 process via foreground Popen + PID-scope kill."""

    def __init__(self, ns_name: str | None = None, qnum: int = 200):
        self.ns_name = ns_name
        self._qnum = qnum
        self._proc: subprocess.Popen | None = None
        self._pid: int | None = None
        self._temp_files: list[str] = []
        self._launcher = Nfqws2Launcher(ns_name)
        self.last_debug_log: str | None = None
        self.last_out_log: Path | None = None

    def _launch(self, config_arg: str, *, stop_first: bool = True) -> None:
        """Start nfqws2 in foreground via Nfqws2Launcher.

        stop_first=True clears any prior process/temps. Callers that just
        created a temp config and appended it to ``_temp_files`` must pass
        stop_first=False (and call ``stop()`` themselves beforehand),
        otherwise ``stop()`` deletes the config before nfqws2 can read it.
        """
        if stop_first:
            self.stop()

        self._launcher.last_debug_log = self.last_debug_log
        result = self._launcher.foreground(config_arg)
        self._proc = result.proc
        self._pid = result.pid
        self.last_out_log = result.out_log

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
                log.info("%s", f"  [nfqws2 debug] {dbg_path}")
        for lua in get_lua_init_scripts():
            if os.path.exists(lua):
                lines.append(f"--lua-init=@{lua}")

        from blockchecks.engine.blob_aliases import sanitize_strategy_for_nfqws2

        strategy = sanitize_strategy_for_nfqws2(
            strategy, lines, BLOB_DIR, extra_names=blobs
        )

        if hostlist:
            fd, hostlist_path = tempfile.mkstemp(prefix="bs_hostlist_", suffix=".txt")
            try:
                with os.fdopen(fd, "w") as f:
                    for d in hostlist:
                        f.write(f"{d}\n")
                os.chmod(hostlist_path, 0o644)
                lines.append(f"--hostlist={hostlist_path}")
                self._temp_files.append(hostlist_path)
            except Exception:
                try:
                    os.unlink(hostlist_path)
                except OSError:
                    pass
                raise

        if strategy.strip().startswith("--"):
            from blockchecks.engine.conf_builder import split_cli_args

            lines.extend(split_cli_args(strategy))
        else:
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

    def _kill_owned_nfqws2(self) -> None:
        """Stop nfqws2 without killpg (EPERM on overflow-uid daemons)."""
        if self.ns_name:
            from blockchecks.service.metrics import pkill_nfqws2_in_ns

            pkill_nfqws2_in_ns(self.ns_name)
            return
        if self._pid is None:
            return
        from blockchecks.service.metrics import pkill_host_process_tree

        n = pkill_host_process_tree(self._pid)
        log.debug("host nfqws2 tree kill wrapper_pid=%s killed=%s", self._pid, n)

    def stop(self) -> None:
        """Kill owned nfqws2 via PID-scoped kill; unlink temp files."""
        self._kill_owned_nfqws2()
        self._pid = None

        if self._proc is not None:
            try:
                self._proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    self._proc.kill()
                    self._proc.wait(timeout=1)
                except (ProcessLookupError, OSError) as exc:
                    log.debug("nfqws2 Popen kill/wait failed: %s", exc)
            except (ProcessLookupError, OSError) as exc:
                log.debug("nfqws2 Popen wait failed: %s", exc)
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
