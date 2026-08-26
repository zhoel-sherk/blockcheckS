"""Lua bridge file IPC under /dev/shm: strategy.id/gen and events.ndjson."""

from __future__ import annotations

import errno
import json
import logging
import os
import shutil
import subprocess as sp
import time
from dataclasses import dataclass
from pathlib import Path

from blockchecks.engine.config import SHM_BASE

log = logging.getLogger(__name__)
_world_warned: set[str] = set()
_setfacl_available: bool | None = None


class IpcPermissionError(OSError):
    """IPC path could not be made accessible to nfqws2 overflow-uid."""


class IpcPublishError(OSError):
    """IPC publish failed; caller should stop the batch early."""


#: uid, под которым nfqws2 работает внутри ns (setuid overflow-uid; см. лог
#: демона «Running as UID=2147483647»). НЕ совпадает с системным nobody!
NFQWS2_OVERFLOW_UID = int(
    os.environ.get("BLOCKCHECKS_NFQWS2_UID", "2147483647")
)


def _setfacl_usable() -> bool:
    """Probe setfacl once per process; avoid spawning subprocess on every publish."""
    global _setfacl_available
    if _setfacl_available is not None:
        return _setfacl_available
    try:
        proc = sp.run(
            ["setfacl", "--version"],
            capture_output=True,
            timeout=2,
        )
    except (OSError, sp.TimeoutExpired) as exc:
        log.debug("IPC setfacl probe unavailable (%s)", exc)
        _setfacl_available = False
        return False
    _setfacl_available = proc.returncode == 0
    return _setfacl_available


def _chmod_or_sudo(path: Path, mode: int, *, is_dir: bool) -> bool:
    """Try os.chmod; on failure retry via passwordless sudo. Return True on success."""
    try:
        os.chmod(path, mode)
        return True
    except OSError as exc:
        log.warning("IPC chmod %s to %o failed (%s) — retrying via sudo", path, mode, exc)
    fix = sp.run(
        ["sudo", "-n", "chmod", "-R", "a+rwX" if is_dir else "a+rw", str(path)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if fix.returncode != 0:
        log.warning(
            "IPC sudo-chmod %s failed rc=%d stderr=%r",
            path,
            fix.returncode,
            fix.stderr.strip()[:200],
        )
        return False
    return True


def _apply_setfacl(path: Path, *, is_dir: bool) -> bool:
    if not _setfacl_usable():
        return False
    perm = "rwx" if is_dir else "rw"
    spec = f"u:{NFQWS2_OVERFLOW_UID}:{perm},u:nobody:{perm}"
    try:
        proc = sp.run(
            ["setfacl", "-m", spec, str(path)],
            check=False,
            capture_output=True,
            timeout=2,
        )
    except (OSError, sp.TimeoutExpired) as exc:
        log.warning("IPC setfacl %s failed (%s); falling back to world-writable", path, exc)
        return False
    if proc.returncode == 0:
        return True
    log.warning(
        "IPC setfacl %s failed rc=%d stderr=%r; falling back to world-writable",
        path,
        proc.returncode,
        (proc.stderr or b"").decode(errors="replace").strip()[:200],
    )
    return False


def _ipc_relax_for_nobody(path: Path, *, is_dir: bool) -> None:
    """Дать nfqws2 (setuid overflow-uid) доступ к IPC без world-writable.

    Урок 25.08: ACL для системного `nobody` бесполезен — демон работает под
    overflow-uid 2147483647. Если setfacl недоступен/не сработал — честный
    фолбэк 0777/0666 (старое рабочее поведение) с однократным warning.
    При полном провале цепочки — raise, иначе APPLIED теряются молча.
    """
    mode = 0o770 if is_dir else 0o660
    _chmod_or_sudo(path, mode, is_dir=is_dir)

    if _apply_setfacl(path, is_dir=is_dir):
        return

    world = 0o777 if is_dir else 0o666
    if not _chmod_or_sudo(path, world, is_dir=is_dir):
        raise IpcPermissionError(
            errno.EACCES,
            f"IPC {path}: chmod, sudo-chmod, setfacl, and world-writable fallback all failed",
        )

    key = str(path.parent if not is_dir else path)
    if key not in _world_warned:
        _world_warned.add(key)
        log.warning(
            "IPC %s is world-writable (no ACL for overflow-uid %d); unsafe on multi-user hosts",
            path,
            NFQWS2_OVERFLOW_UID,
        )


def _rmtree_logged(path: Path, *, context: str) -> None:
    if not path.exists():
        return
    shutil.rmtree(path, ignore_errors=True)
    if path.exists():
        log.warning("IPC rmtree %s left leftovers at %s", context, path)


@dataclass(frozen=True)
class BridgeEvent:
    event: str
    gen: int = 0
    id: int = 0
    reason: str = ""
    ttl: int = 0
    # scan_pick sets matched=N (instances executed for this id). -1 = field
    # absent (upstream/older Lua) — treat as "applied" for compatibility.
    matched: int = -1
    raw: dict | None = None

    @classmethod
    def from_line(cls, line: str) -> BridgeEvent | None:
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        return cls(
            event=str(data.get("event") or ""),
            gen=int(data.get("gen") or 0),
            id=int(data.get("id") or 0),
            reason=str(data.get("reason") or ""),
            ttl=int(data.get("ttl") or 0),
            matched=int(data["matched"]) if "matched" in data else -1,
            raw=data,
        )

    def is_rst_in(self) -> bool:
        """True if this event is a DPI-injected inbound RST (scan_bridge)."""
        return self.event == "STRATEGY_FAIL" and self.reason == "rst_in"

    def is_applied(self) -> bool:
        """True for an APPLIED event that actually executed >=1 instance.

        matched == 0 means scan_pick ran but no instance carried the active
        strategy id (nothing was sent) — that must not count as applied.
        matched == -1 (field absent, older Lua) keeps the legacy meaning.
        """
        return self.event == "APPLIED" and self.matched != 0

    def to_dict(self) -> dict:
        """Serializable dict for API/SSE consumers (mirrors vars())."""
        return {
            "event": self.event,
            "gen": self.gen,
            "id": self.id,
            "reason": self.reason,
            "ttl": self.ttl,
            "matched": self.matched,
        }


@dataclass(frozen=True)
class BridgePaths:
    base: Path

    @property
    def strategy_id(self) -> Path:
        return self.base / "strategy.id"

    @property
    def strategy_gen(self) -> Path:
        return self.base / "strategy.gen"

    @property
    def strategy_cmd(self) -> Path:
        return self.base / "strategy.cmd"

    @property
    def strategy_ready(self) -> Path:
        return self.base / "strategy.ready"

    @property
    def events(self) -> Path:
        return self.base / "events.ndjson"

    @property
    def heartbeat(self) -> Path:
        return self.base / "heartbeat"


class LuaBridge:
    """File IPC to a persistent nfqws2 daemon (WRITABLE + strategy.id/gen)."""

    def __init__(self, ns_name: str, shm_base: Path | None = None) -> None:
        base = Path(shm_base or SHM_BASE)
        self.ns_name = ns_name
        self.paths = BridgePaths(base / ns_name)

    def setup(self) -> None:
        self.paths.base.mkdir(parents=True, exist_ok=True)
        # nfqws2 drops privileges to nobody/overflow (uid 65534) and must be
        # able to chdir + create staging files here. 0o755 (root:root) lets it
        # chdir but NOT create .staging / strategy.* files → the daemon dies or
        # the bridge never sees APPLIED. World-writable dir fixes both.
        _ipc_relax_for_nobody(self.paths.base, is_dir=True)
        self._init_events()

    def _init_events(self) -> None:
        # nfqws2 drops privileges (setuid nobody/overflow) after init and must
        # be able to APPEND APPLIED/STRATEGY_FAIL events. The file is created
        # by Python as root — make it world-writable or Lua's io.open("a")
        # returns nil and the strategy-selection events are silently lost.
        self.paths.events.write_text("", encoding="utf-8")
        _ipc_relax_for_nobody(self.paths.events, is_dir=False)

    def teardown(self) -> None:
        _rmtree_logged(self.paths.base, context="teardown")

    def publish(self, strategy_id: int, gen: int, cmd: str | None = None) -> None:
        """Atomically publish strategy index + generation (os.replace).

        Writes all payload files in a staging dir, chmods for the dropped-uid
        nfqws2 process (nobody), then replaces them before strategy.ready so
        Lua never observes an inconsistent set.

        Commit order matters: gen FIRST, then cmd, then id, ready last.
        The Lua-side fence (bs_read_strategy_ipc) accepts a read only when
        strategy.ready == strategy.gen. With id replaced before gen there was
        a window where ready == gen (both stale) but id was already new —
        Lua applied the new strategy yet reported the stale gen, and the
        Python-side ``drain_events(since_gen=gen)`` filter dropped that
        probe's APPLIED event ("bridge PASS without APPLIED"). With gen
        committed first, every intermediate state fails the fence and readers
        keep their previous consistent snapshot instead.
        """
        try:
            self._publish_impl(strategy_id, gen, cmd)
        except IpcPermissionError:
            raise
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                log.error(
                    "IPC publish aborted: no space left on device (ENOSPC) at %s",
                    self.paths.base,
                )
            else:
                log.error("IPC publish failed at %s: %s", self.paths.base, exc)
            raise IpcPublishError(
                f"IPC publish failed for {self.ns_name}: {exc}"
            ) from exc

    def _publish_impl(self, strategy_id: int, gen: int, cmd: str | None) -> None:
        _ipc_relax_for_nobody(self.paths.base, is_dir=True)
        if self.paths.events.is_file():
            _ipc_relax_for_nobody(self.paths.events, is_dir=False)

        staging = self.paths.base / f".staging.{gen}"
        if staging.exists():
            _rmtree_logged(staging, context="publish pre-staging")
        staging.mkdir(parents=True, exist_ok=True)
        _ipc_relax_for_nobody(staging, is_dir=True)

        staged_files: dict[str, Path] = {
            "strategy.id": staging / "strategy.id",
            "strategy.gen": staging / "strategy.gen",
            "strategy.ready": staging / "strategy.ready",
        }
        staged_files["strategy.id"].write_text(f"{strategy_id}\n", encoding="utf-8")
        staged_files["strategy.gen"].write_text(f"{gen}\n", encoding="utf-8")
        if cmd:
            staged_files["strategy.cmd"] = staging / "strategy.cmd"
            staged_files["strategy.cmd"].write_text(cmd.rstrip() + "\n", encoding="utf-8")
        staged_files["strategy.ready"].write_text(f"{gen}\n", encoding="utf-8")

        for src in staged_files.values():
            _ipc_relax_for_nobody(src, is_dir=False)

        # Commit payload first; strategy.ready is the publish fence for Lua.
        for name in ("strategy.gen", "strategy.cmd", "strategy.id"):
            src = staged_files.get(name)
            if src is not None and src.is_file():
                dst = self.paths.base / name
                os.replace(src, dst)
                _ipc_relax_for_nobody(dst, is_dir=False)

        ready_src = staged_files["strategy.ready"]
        ready_dst = self.paths.base / "strategy.ready"
        os.replace(ready_src, ready_dst)
        _ipc_relax_for_nobody(ready_dst, is_dir=False)

        _rmtree_logged(staging, context="publish post-staging")

    def drain_events(
        self, since_gen: int = 0, expect_id: int | None = None
    ) -> list[BridgeEvent]:
        """Read events written by Lua since *since_gen*.

        An event is accepted when its generation is current OR when it was
        emitted for the exact strategy id we published (expect_id). The id
        branch rescues APPLIED events written by a daemon whose cached
        _G.bs_active_gen lagged one publish behind (fence nil-read window):
        those carry a stale gen but are unambiguously ours by id.
        """
        if not self.paths.events.is_file():
            return []
        out: list[BridgeEvent] = []
        for line in self.paths.events.read_text(encoding="utf-8").splitlines():
            ev = BridgeEvent.from_line(line)
            if not ev:
                continue
            if ev.gen >= since_gen or (expect_id is not None and ev.id == expect_id):
                out.append(ev)
        return out

    def truncate_events(self) -> None:
        self._init_events()

    def heartbeat_age(self, *, now: float | None = None) -> float | None:
        """Seconds since the daemon's last heartbeat, or None if unknown.

        The Lua timer (init.lua) rewrites ``heartbeat`` (epoch seconds) every
        ~200ms while nfqws2 is alive. A stale value means the daemon is dead
        or wedged — check BEFORE burning a probe on queue-bypassed traffic.
        """
        try:
            raw = self.paths.heartbeat.read_text(encoding="utf-8").strip()
            ts = int(raw)
        except (OSError, ValueError):
            return None
        ref = time.time() if now is None else now
        return max(0.0, float(ref - ts))
