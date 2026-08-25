"""Start and stop nfqws2: daemon @config, or foreground Popen plus killpg."""

from __future__ import annotations

import logging
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
from blockchecks.service.nfqws2_settle import (
    _wait_nfqws2_gone,
    wait_nfqws2_ready,
)

log = logging.getLogger(__name__)


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
            log.info("%s", f"  [nfqws2 debug] {dbg_path}")
    if changed:
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except OSError:
            return None
    return dbg_path if dbg else None


def _reclaim_debug_log(dbg_path: str | None) -> None:
    """Chown a just-created nfqws2 --debug log back to SUDO_UID/GID.

    nfqws2 drops privileges (setuid overflow-uid) and creates the log itself,
    so it stays root/overflow-owned unless repaired after launch.
    """
    if not dbg_path:
        return
    try:
        from blockchecks.engine.paths import reclaim_sudo_ownership

        reclaim_sudo_ownership(Path(dbg_path))
    except Exception as exc:
        log.warning("nfqws2 debug log reclaim failed (%s): %s", dbg_path, exc)


def open_out_capture(tag: str):
    """Open stdout/stderr capture file for an nfqws2 launch.

    Bind failures (`nfq_create_queue(): ...`) are printed by nfqws2 to
    **stdout** — NOT to ``--debug=@file``. With --daemon and DEVNULL pipes
    that message was lost, making daemon deaths look silent (zapret2#300).
    Files match the ``nfqws2_*.log`` gc glob, so retention applies.

    Returns ``(fh, path)``; fh=None on failure. Caller must close fh after
    Popen (the child keeps its inherited fd).
    """
    from blockchecks.engine.paths import RUNTIME_LOGS_DIR

    try:
        RUNTIME_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = RUNTIME_LOGS_DIR / f"nfqws2_out_{tag}_{ts}.log"
        # noqa: SIM115 — файл намеренно живёт дольше функции: его наследует
        # дочерний процесс (stdout демона), закрывает вызывающий после Popen.
        fh = open(path, "ab", buffering=0)  # noqa: SIM115
        fh.write(f"=== nfqws2 launch tag={tag} {ts}\n".encode())
        return fh, path
    except OSError as exc:
        log.warning("%s", f"  WARNING: out-capture disabled for {tag}: {exc}")
        return None, None


def _prune_out_logs() -> None:
    """Apply keep-N retention to out/debug captures after each launch."""
    try:
        from blockchecks.engine.gc import prune_nfqws2_debug_logs

        prune_nfqws2_debug_logs()
    except Exception as exc:
        log.warning("nfqws2 out-log prune failed: %s", exc)


def start_daemon(
    ns_name: str,
    config_path: str,
    kill_existing: bool = True,
    *,
    settle_max: float | None = None,
    settle_poll: float | None = None,
    min_procs: int = 1,
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
        dbg_path = inject_debug_and_daemon(tmp_conf, tag=ns_name)
        if kill_existing:
            # Scoped kill: netns exec pkill would hit nfqws2 host-wide (no PID ns).
            from blockchecks.service.metrics import pkill_nfqws2_in_ns

            pkill_nfqws2_in_ns(ns_name)
            # pkill is async: the old daemon may still hold the NFQUEUE socket
            # when the new one binds, causing the new daemon to die (settle
            # spikes, "PASS without APPLIED" warnings). Wait for it to actually
            # disappear before starting the replacement.
            _wait_nfqws2_gone(ns_name, max_wait=2.0)
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
        # Ядро освобождает NFQUEUE-сокет после pkill с задержкой; при раннем
        # ребуте новый демон умирает с nfq_create_queue(): Operation not
        # permitted (zapret2#300). Ретраим бинд с backoff — stdout-захват
        # даёт надёжный маркер именно этой причины.
        max_bind_attempts = 5
        settle = 0.0
        from blockchecks.service.nfqws2_settle import nfqws2_count_in_ns

        procs_before = nfqws2_count_in_ns(ns_name)
        for attempt in range(1, max_bind_attempts + 1):
            out_fh, out_path = open_out_capture(ns_name)
            try:
                subprocess.Popen(
                    cmd,
                    stdout=out_fh if out_fh is not None else subprocess.DEVNULL,
                    stderr=subprocess.STDOUT if out_fh is not None else subprocess.DEVNULL,
                )
            finally:
                if out_fh is not None:
                    out_fh.close()
                _prune_out_logs()
            settle = wait_nfqws2_ready(
                ns_name, max_wait=settle_max, poll_interval=settle_poll, min_procs=min_procs
            )
            _reclaim_debug_log(dbg_path)
            # Liveness: /proc-сканирование слепо к root-owned процессам при
            # user-запуске (readlink ns/net → EPERM), поэтому первичный
            # маркер — строка "setting copy_packet mode" в stdout-захвате;
            # /proc-count используется только как дополнительный сигнал.
            try:
                out_txt = (
                    out_path.read_text(errors="replace")[:2000]
                    if out_path is not None and out_path.exists()
                    else ""
                )
            except OSError:
                out_txt = ""
            alive = (
                "setting copy_packet mode" in out_txt
                or nfqws2_count_in_ns(ns_name) > procs_before
            )
            if alive or attempt == max_bind_attempts:
                break
            if "Operation not permitted" in out_txt and "nfq_create_queue" in out_txt:
                backoff = min(2.0 * attempt, 6.0)
                log.warning(
                    "%s",
                    f"  [nfqws2] {ns_name}: queue 200 busy after pkill "
                    f"(attempt {attempt}/{max_bind_attempts}) — retry in {backoff:.1f}s",
                )
                time.sleep(backoff)
            else:
                break  # иная причина старта — ретрай бинда не поможет
        _prune_out_logs()
        return settle
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
        self.last_out_log: Path | None = None

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

        # Bind-retry (тот же маркер, что в start_daemon): ядро освобождает
        # NFQUEUE-сокет после pkill с задержкой → первый запуск может упасть
        # с nfq_create_queue(): Operation not permitted.
        max_bind_attempts = 4
        last_err: RuntimeError | None = None
        for attempt in range(1, max_bind_attempts + 1):
            out_fh, out_path = open_out_capture(self.ns_name or "host")
            self.last_out_log = out_path
            try:
                self._proc = subprocess.Popen(
                    args,
                    stdout=out_fh if out_fh is not None else subprocess.DEVNULL,
                    # Never PIPE: unread buffer blocks a chatty/debug nfqws2.
                    # Init/errors go to --debug=@file when enabled; bind errors
                    # (nfq_create_queue) go to stdout — captured in out-file.
                    stderr=subprocess.STDOUT if out_fh is not None else subprocess.DEVNULL,
                    start_new_session=True,
                )
            finally:
                if out_fh is not None:
                    out_fh.close()
                    _prune_out_logs()
            self._pid = self._proc.pid
            if self.ns_name:
                wait_nfqws2_ready(self.ns_name)
            else:
                time.sleep(0.1)
            _reclaim_debug_log(self.last_debug_log)

            if self._proc.poll() is None:
                last_err = None
                break
            tail_txt = ""
            for log_path in (
                self.last_out_log,
                Path(self.last_debug_log) if self.last_debug_log else None,
            ):
                if log_path and os.path.exists(log_path):
                    try:
                        tail_txt += Path(log_path).read_text(errors="replace")[-300:]
                    except OSError:
                        pass
            bind_busy = (
                "Operation not permitted" in tail_txt
                and "nfq_create_queue" in tail_txt
            )
            self._proc = None
            self._pid = None
            if not bind_busy or attempt == max_bind_attempts:
                last_err = RuntimeError(
                    "nfqws2 failed to start (exited immediately)"
                    + (f"; out_tail={tail_txt!r}" if tail_txt else "")
                )
                break
            backoff = min(2.0 * attempt, 6.0)
            log.warning(
                "%s",
                f"  [nfqws2] {self.ns_name or 'host'}: queue busy after stop "
                f"(attempt {attempt}/{max_bind_attempts}) — retry in {backoff:.1f}s",
            )
            time.sleep(backoff)
        if last_err is not None:
            raise last_err

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

        # Full CLI strategy lines (e.g. custom list_http.txt entries like
        # "--payload=http_req --lua-desync=http_hostcase") carry their own
        # payload + desync and must not be wrapped again — otherwise nfqws2
        # gets a duplicate --payload / a garbage --lua-desync and exits.
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
