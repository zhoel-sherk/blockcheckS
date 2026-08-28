"""Unified nfqws2 launch: daemon and foreground with shared bind-retry."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
import weakref
from dataclasses import dataclass
from pathlib import Path

from blockchecks.engine.config import (
    NFQWS2_SETTLE_MAX,
    get_nfqws2_bin,
    nfqws2_debug_conf_line,
)
from blockchecks.service.nfqws2_settle import (
    NFQWS2_BIND_MARKER,
    _wait_nfqws2_gone,
    nfqws2_bind_retry_backoff,
    nfqws2_bind_retry_should_continue,
    nfqws2_count_in_ns,
    nfqws2_out_shows_bind,
    resolve_nfqws2_pids,
    wait_nfqws2_bind_proof,
    wait_nfqws2_ready,
)

log = logging.getLogger(__name__)

#: Попытки бинда NFQUEUE при "queue busy" (сокет освобождается ядром с задержкой)
NFQWS2_BIND_ATTEMPTS = 5

#: Fire-and-forget daemon Popens — poll() to reap zombies (RT-7).
_daemon_popens: weakref.WeakSet[subprocess.Popen] = weakref.WeakSet()


def _reap_daemon_popens() -> None:
    """Poll tracked daemon Popens so exited children do not accumulate as zombies."""
    for proc in list(_daemon_popens):
        try:
            proc.poll()
        except Exception as exc:
            log.debug("daemon Popen poll failed: %s", exc)


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
    """Chown a just-created nfqws2 --debug log back to SUDO_UID/GID."""
    if not dbg_path:
        return
    try:
        from blockchecks.engine.paths import reclaim_sudo_ownership

        reclaim_sudo_ownership(Path(dbg_path))
    except Exception as exc:
        log.warning("nfqws2 debug log reclaim failed (%s): %s", dbg_path, exc)


def open_out_capture(tag: str):
    """Open stdout/stderr capture file for an nfqws2 launch.

    Bind failures (``nfq_create_queue()``) go to stdout — NOT ``--debug=@file``.
    Returns ``(fh, path)``; fh=None on failure. Caller must close fh after Popen.
    """
    from blockchecks.engine.paths import RUNTIME_LOGS_DIR

    try:
        RUNTIME_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = RUNTIME_LOGS_DIR / f"nfqws2_out_{tag}_{ts}.log"
        # noqa: SIM115 — файл наследует дочерний процесс (stdout демона).
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


def _read_out_tail(out_path: Path | None, *, limit: int = 2000) -> str:
    if out_path is None or not out_path.exists():
        return ""
    try:
        return out_path.read_text(errors="replace")[:limit]
    except OSError:
        return ""


def _build_cmd(ns_name: str | None, config_arg: str) -> list[str]:
    args = [get_nfqws2_bin(), config_arg]
    if ns_name:
        return ["sudo", "-n", "ip", "netns", "exec", ns_name] + args
    return ["sudo", "-n"] + args


def _build_daemon_cmd(ns_name: str, tmp_conf: str) -> list[str]:
    return [
        "sudo",
        "ip",
        "netns",
        "exec",
        ns_name,
        get_nfqws2_bin(),
        f"@{tmp_conf}",
    ]


@dataclass
class ForegroundLaunch:
    """Result of a foreground nfqws2 launch."""

    proc: subprocess.Popen
    pid: int
    out_log: Path | None


class Nfqws2Launcher:
    """Owns bind-retry, out-capture, settle, and PID resolution for nfqws2."""

    def __init__(self, ns_name: str | None = None):
        self.ns_name = ns_name
        self.last_debug_log: str | None = None
        self.last_out_log: Path | None = None

    def foreground(self, config_arg: str) -> ForegroundLaunch:
        """Start nfqws2 in foreground with bind-retry and settle proof."""
        max_bind_attempts = NFQWS2_BIND_ATTEMPTS
        last_err: RuntimeError | None = None
        baseline: frozenset[int] = (
            frozenset(resolve_nfqws2_pids(self.ns_name)) if self.ns_name else frozenset()
        )
        proc: subprocess.Popen | None = None
        pid: int | None = None
        for attempt in range(1, max_bind_attempts + 1):
            out_fh, out_path = open_out_capture(self.ns_name or "host")
            self.last_out_log = out_path
            try:
                proc = subprocess.Popen(
                    _build_cmd(self.ns_name, config_arg),
                    stdout=out_fh if out_fh is not None else subprocess.DEVNULL,
                    stderr=subprocess.STDOUT if out_fh is not None else subprocess.DEVNULL,
                    start_new_session=True,
                )
            finally:
                if out_fh is not None:
                    out_fh.close()
                    _prune_out_logs()
            pid = proc.pid
            if self.ns_name:
                settle_max = NFQWS2_SETTLE_MAX
                settle = wait_nfqws2_ready(self.ns_name, max_wait=settle_max)
                count = nfqws2_count_in_ns(self.ns_name)
                bound = nfqws2_out_shows_bind(self.last_out_log)
                if settle >= settle_max and count == 0:
                    if not bound:
                        raise RuntimeError(
                            f"nfqws2 not visible in {self.ns_name} after settle "
                            f"({settle:.2f}s >= {settle_max:.2f}s)"
                        )
                    log.debug(
                        "%s",
                        f"  [nfqws2] {self.ns_name}: bind marker present with "
                        "count=0 — treat as alive (overflow-uid /proc EPERM)",
                    )
                if not wait_nfqws2_bind_proof(
                    self.ns_name,
                    baseline_pids=baseline,
                    out_path=self.last_out_log,
                ):
                    log.warning(
                        "%s",
                        f"  [nfqws2] {self.ns_name}: no bind proof after settle "
                        f"— process visible but NFQUEUE may not be ready",
                    )
                if real := resolve_nfqws2_pids(self.ns_name, baseline):
                    pid = real[0]
            else:
                time.sleep(0.1)
            _reclaim_debug_log(self.last_debug_log)

            if proc.poll() is None:
                last_err = None
                break
            tail_txt = _read_out_tail(self.last_out_log, limit=300)
            if self.last_debug_log and os.path.exists(self.last_debug_log):
                try:
                    tail_txt += Path(self.last_debug_log).read_text(errors="replace")[-300:]
                except OSError:
                    pass
            should_retry, reason = nfqws2_bind_retry_should_continue(
                tail_txt,
                attempt=attempt,
                max_attempts=max_bind_attempts,
                succeeded=False,
            )
            proc = None
            pid = None
            if not should_retry:
                last_err = RuntimeError(
                    "nfqws2 failed to start (exited immediately)"
                    + (f"; out_tail={tail_txt!r}" if tail_txt else "")
                )
                break
            backoff = nfqws2_bind_retry_backoff(attempt)
            log.warning(
                "%s",
                f"  [nfqws2] {self.ns_name or 'host'}: {reason} after stop "
                f"(attempt {attempt}/{max_bind_attempts}) — retry in {backoff:.1f}s",
            )
            time.sleep(backoff)
        if last_err is not None:
            raise last_err
        assert proc is not None and pid is not None
        return ForegroundLaunch(proc=proc, pid=pid, out_log=self.last_out_log)

    def daemon(
        self,
        config_path: str,
        kill_existing: bool = True,
        *,
        settle_max: float | None = None,
        settle_poll: float | None = None,
        min_procs: int = 1,
    ) -> float:
        """Launch nfqws2 in daemon mode inside netns. Returns settle elapsed seconds."""
        if not self.ns_name:
            raise ValueError("daemon launch requires ns_name")
        ns_name = self.ns_name

        _fd, tmp_conf = tempfile.mkstemp(prefix="bs_nfq_", suffix=".conf")
        os.close(_fd)
        launched = False
        last_out_path: Path | None = None
        baseline: frozenset[int] = frozenset()
        try:
            shutil.copy2(config_path, tmp_conf)
            dbg_path = inject_debug_and_daemon(tmp_conf, tag=ns_name)
            drain_ok = True
            if kill_existing:
                from blockchecks.service.metrics import pkill_nfqws2_in_ns

                pkill_nfqws2_in_ns(ns_name)
                drain_ok = _wait_nfqws2_gone(ns_name, max_wait=2.0)
                if not drain_ok:
                    log.warning(
                        "%s",
                        f"  [nfqws2] {ns_name}: prior daemon still visible after "
                        f"pkill drain — bind retries likely",
                    )
            else:
                baseline = frozenset(resolve_nfqws2_pids(ns_name))

            cmd = _build_daemon_cmd(ns_name, tmp_conf)
            max_bind_attempts = NFQWS2_BIND_ATTEMPTS
            settle = 0.0
            _reap_daemon_popens()
            for attempt in range(1, max_bind_attempts + 1):
                out_fh, out_path = open_out_capture(ns_name)
                last_out_path = out_path
                proc: subprocess.Popen | None = None
                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=out_fh if out_fh is not None else subprocess.DEVNULL,
                        stderr=subprocess.STDOUT if out_fh is not None else subprocess.DEVNULL,
                    )
                    if proc is not None:
                        launched = True
                        _daemon_popens.add(proc)
                        _reap_daemon_popens()
                finally:
                    if out_fh is not None:
                        out_fh.close()
                    _prune_out_logs()
                settle = wait_nfqws2_ready(
                    ns_name, max_wait=settle_max, poll_interval=settle_poll, min_procs=min_procs
                )
                _reclaim_debug_log(dbg_path)
                out_txt = _read_out_tail(out_path)
                alive = NFQWS2_BIND_MARKER in out_txt or bool(resolve_nfqws2_pids(ns_name, baseline))
                should_retry, reason = nfqws2_bind_retry_should_continue(
                    out_txt,
                    attempt=attempt,
                    max_attempts=max_bind_attempts,
                    drain_ok=drain_ok,
                    succeeded=alive,
                )
                if not should_retry:
                    break
                backoff = nfqws2_bind_retry_backoff(attempt)
                log.warning(
                    "%s",
                    f"  [nfqws2] {ns_name}: {reason} after pkill "
                    f"(attempt {attempt}/{max_bind_attempts}) — retry in {backoff:.1f}s",
                )
                time.sleep(backoff)
            _prune_out_logs()
            return settle
        finally:
            if launched and not (
                nfqws2_out_shows_bind(last_out_path) or resolve_nfqws2_pids(ns_name, baseline)
            ):
                wait_nfqws2_bind_proof(
                    ns_name,
                    baseline_pids=baseline,
                    out_path=last_out_path,
                )
            try:
                os.unlink(tmp_conf)
            except OSError:
                pass


def start_daemon(
    ns_name: str,
    config_path: str,
    kill_existing: bool = True,
    *,
    settle_max: float | None = None,
    settle_poll: float | None = None,
    min_procs: int = 1,
) -> float:
    """Module-level daemon launch (backward compat)."""
    return Nfqws2Launcher(ns_name).daemon(
        config_path,
        kill_existing=kill_existing,
        settle_max=settle_max,
        settle_poll=settle_poll,
        min_procs=min_procs,
    )
