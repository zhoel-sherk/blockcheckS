"""nfqws2 Lua bridge — /dev/shm IPC + scan_pick batch conf (no C fork)."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from blockchecks.engine.blob_aliases import append_blob_cli_lines, extract_blob_names
from blockchecks.engine.config import (
    BLOB_DIR,
    NFQUEUE_TCP,
    PROJECT_DIR,
    SHM_BASE,
    get_blockchecks_lua_scripts,
    get_lua_init_scripts,
)
from blockchecks.engine.generators.base import StrategyItem

REPO_LUA_DIR = Path(PROJECT_DIR) / "lua" / "blockchecks"


@dataclass(frozen=True)
class BridgeEvent:
    event: str
    gen: int = 0
    id: int = 0
    reason: str = ""
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
            raw=data,
        )


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


class LuaBridge:
    """File IPC to a persistent nfqws2 daemon (WRITABLE + strategy.id/gen)."""

    def __init__(self, ns_name: str, shm_base: Path | None = None) -> None:
        base = Path(shm_base or SHM_BASE)
        self.ns_name = ns_name
        self.paths = BridgePaths(base / ns_name)

    def setup(self) -> None:
        self.paths.base.mkdir(parents=True, exist_ok=True)
        os.chmod(self.paths.base, 0o755)
        self.paths.events.write_text("", encoding="utf-8")

    def teardown(self) -> None:
        shutil.rmtree(self.paths.base, ignore_errors=True)

    def publish(self, strategy_id: int, gen: int, cmd: str | None = None) -> None:
        """Atomically publish strategy index + generation (os.replace)."""
        staging = self.paths.base / f".staging.{gen}"
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True, exist_ok=True)

        (staging / "strategy.id").write_text(f"{strategy_id}\n", encoding="utf-8")
        (staging / "strategy.gen").write_text(f"{gen}\n", encoding="utf-8")
        if cmd:
            (staging / "strategy.cmd").write_text(cmd.rstrip() + "\n", encoding="utf-8")
        (staging / "strategy.ready").write_text(f"{gen}\n", encoding="utf-8")

        for name in ("strategy.id", "strategy.gen", "strategy.cmd", "strategy.ready"):
            src = staging / name
            if src.is_file():
                os.replace(src, self.paths.base / name)

        shutil.rmtree(staging, ignore_errors=True)

    def drain_events(self, since_gen: int = 0) -> list[BridgeEvent]:
        if not self.paths.events.is_file():
            return []
        out: list[BridgeEvent] = []
        for line in self.paths.events.read_text(encoding="utf-8").splitlines():
            ev = BridgeEvent.from_line(line)
            if ev and ev.gen >= since_gen:
                out.append(ev)
        return out

    def truncate_events(self) -> None:
        self.paths.events.write_text("", encoding="utf-8")


def stage_blockchecks_lua(ipc_dir: Path, extra: list[str] | None = None) -> list[Path]:
    """Copy bridge Lua into WRITABLE tree (nfqws2 drops privs; repo paths may be unreadable)."""
    lua_dir = ipc_dir / "lua"
    lua_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(lua_dir, 0o755)
    staged: list[Path] = []
    for src in get_blockchecks_lua_scripts(extra):
        dst = lua_dir / src.name
        shutil.copy2(src, dst)
        os.chmod(dst, 0o644)
        staged.append(dst)
    return staged


def blockchecks_lua_init_lines(extra: list[str] | None = None) -> list[str]:
    """--lua-init lines for blockchecks bridge scripts (after zapret trio)."""
    lines: list[str] = []
    for path in get_blockchecks_lua_scripts(extra):
        if path.is_file():
            lines.append(f"--lua-init=@{path}")
    return lines


def _strategy_filter_lines(protocol: str) -> list[str]:
    if protocol == "http":
        return [
            f"--qnum={NFQUEUE_TCP}",
            "--filter-tcp=80",
            "--filter-l3=ipv4",
            "--filter-l7=http",
            "--ipcache-lifetime=0",
            "--bind-fix4",
            "--payload=http_req",
        ]
    return [
        f"--qnum={NFQUEUE_TCP}",
        "--filter-tcp=443",
        "--filter-l3=ipv4",
        "--filter-l7=tls",
        "--ipcache-lifetime=0",
        "--bind-fix4",
        "--payload=tls_client_hello",
    ]


def _split_cli_args(raw_line: str) -> list[str]:
    out: list[str] = []
    for arg in raw_line.split(" --"):
        arg = arg.strip()
        if not arg:
            continue
        if not arg.startswith("--"):
            arg = "--" + arg
        out.append(arg)
    return out


def _append_strategy_desyncs(lines: list[str], strategy: str, strategy_n: int) -> None:
    tag = f":strategy={strategy_n}"
    for raw_line in strategy.split("\n"):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        if raw_line.startswith("--"):
            for cli in _split_cli_args(raw_line):
                lines.append(cli)
        else:
            desync = raw_line if ":strategy=" in raw_line else raw_line + tag
            lines.append(f"--lua-desync={desync}")


def build_bridge_conf(
    strategies: list[str],
    ipc_dir: Path,
    *,
    protocol: str = "tls12",
    extra_lua_init: list[str] | None = None,
) -> str:
    """Build nfqws2 flat conf: writable + scan_pick batch with strategy=1..N."""
    lines: list[str] = [
        f"--writable={ipc_dir}",
        f"--qnum={NFQUEUE_TCP}",
    ]
    for lua in get_lua_init_scripts():
        if os.path.isfile(lua):
            lines.append(f"--lua-init=@{lua}")
    for path in stage_blockchecks_lua(ipc_dir, extra_lua_init):
        lines.append(f"--lua-init=@{path}")
    lines.extend(_strategy_filter_lines(protocol))
    lines.append("--lua-desync=bs_poll_strategy")
    lines.append("--lua-desync=smart_fallback")
    lines.append("--lua-desync=scan_pick")

    all_blob_names: list[str] = []
    for strat in strategies:
        all_blob_names.extend(extract_blob_names(strat))
    append_blob_cli_lines(lines, all_blob_names, BLOB_DIR)

    for i, strat in enumerate(strategies, start=1):
        _append_strategy_desyncs(lines, strat, i)

    return "\n".join(lines) + "\n"


def write_bridge_conf(
    strategies: list[str],
    ipc_dir: Path,
    *,
    protocol: str = "tls12",
    extra_lua_init: list[str] | None = None,
    tag: str = "bridge",
) -> str:
    """Write bridge conf to a temp file; return path."""
    text = build_bridge_conf(
        strategies, ipc_dir, protocol=protocol, extra_lua_init=extra_lua_init
    )
    fd, path = tempfile.mkstemp(prefix=f"bs_{tag}_", suffix=".conf")
    os.close(fd)
    Path(path).write_text(text, encoding="utf-8")
    return path


@dataclass
class BridgeSession:
    """Per-netns bridge state: one daemon + iptables for a strategy batch."""

    ns_name: str
    strategies: list[str]
    bridge: LuaBridge
    conf_path: str = ""
    iptables_ready: bool = False
    protocol: str = "tls12"
    extra_lua_init: list[str] | None = None

    def boot(self) -> float:
        from blockchecks.engine.services.nfqws2 import start_daemon

        _check_netns_exists(self.ns_name)
        self.bridge.setup()
        if self.conf_path:
            try:
                os.unlink(self.conf_path)
            except OSError:
                pass
        self.conf_path = write_bridge_conf(
            self.strategies,
            self.bridge.paths.base,
            protocol=self.protocol,
            extra_lua_init=self.extra_lua_init,
            tag=self.ns_name,
        )
        settle = start_daemon(self.ns_name, self.conf_path, kill_existing=True)
        if not self.iptables_ready:
            dport = "80" if self.protocol == "http" else "443"
            _bridge_iptables_add(self.ns_name, dport)
            self.iptables_ready = True
        return settle

    def shutdown(self) -> None:
        import subprocess as sp

        sp.run(
            ["sudo", "ip", "netns", "exec", self.ns_name, "pkill", "-9", "nfqws2"],
            capture_output=True,
            check=False,
            timeout=15,
        )
        if self.iptables_ready:
            sp.run(
                ["sudo", "ip", "netns", "exec", self.ns_name, "iptables", "-F", "OUTPUT"],
                capture_output=True,
                check=False,
                timeout=15,
            )
            self.iptables_ready = False
        if self.conf_path:
            try:
                os.unlink(self.conf_path)
            except OSError:
                pass
            self.conf_path = ""
        self.bridge.teardown()


def _netns_tcp_probe_cleanup(ns_name: str) -> None:
    """Drop nfqws2 + flush OUTPUT iptables after classic per-probe runs."""
    import subprocess as sp

    sp.run(
        ["sudo", "ip", "netns", "exec", ns_name, "pkill", "-9", "nfqws2"],
        capture_output=True,
        check=False,
        timeout=15,
    )
    sp.run(
        ["sudo", "ip", "netns", "exec", ns_name, "iptables", "-F", "OUTPUT"],
        capture_output=True,
        check=False,
        timeout=15,
    )


def strategy_text_from_item(item: StrategyItem) -> str:
    """Inline strategy or lua-desync lines extracted from a .conf path."""
    if not item.is_config:
        return item.strategy
    lines: list[str] = []
    for raw in Path(item.strategy).read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if raw.startswith("--lua-desync="):
            lines.append(raw[len("--lua-desync="):])
    return "\n".join(lines)


def _bridge_iptables_add(ns_name: str, dport: str) -> None:
    import subprocess as sp

    _check_netns_exists(ns_name)
    sp.run(
        ["sudo", "ip", "netns", "exec", ns_name, "iptables", "-F", "OUTPUT"],
        capture_output=True,
        check=False,
        timeout=15,
    )
    sp.run(
        [
            "sudo",
            "ip",
            "netns",
            "exec",
            ns_name,
            "iptables",
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            dport,
            "-j",
            "NFQUEUE",
            "--queue-num",
            str(NFQUEUE_TCP),
            "--queue-bypass",
        ],
        capture_output=True,
        check=True,
        timeout=15,
    )


def _check_netns_exists(ns_name: str) -> None:
    import subprocess as sp

    r = sp.run(
        ["sudo", "ip", "netns", "list"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    for line in r.stdout.splitlines():
        if line.strip() == ns_name or line.strip().startswith(ns_name + " "):
            return
    raise NetnsGoneError(
        f"netns {ns_name!r} no longer exists — pool may have been destroyed "
        f"by a concurrent process. Retry or restart the scan."
    )


class NetnsGoneError(RuntimeError):
    """Netns was destroyed while in use by another process."""


def teardown_all_bridge_shm(shm_base: Path | None = None) -> None:
    """Remove all bridge IPC dirs under SHM_BASE (campaign stop cleanup)."""
    base = Path(shm_base or SHM_BASE)
    if base.is_dir():
        shutil.rmtree(base, ignore_errors=True)


@contextmanager
def bridge_worker_session(
    ns_name: str,
    strategies: list[str],
    *,
    protocol: str = "tls12",
    extra_lua_init: list[str] | None = None,
    shm_base: Path | None = None,
) -> Iterator[BridgeSession]:
    session = BridgeSession(
        ns_name=ns_name,
        strategies=strategies,
        bridge=LuaBridge(ns_name, shm_base=shm_base),
        protocol=protocol,
        extra_lua_init=extra_lua_init,
    )
    try:
        session.boot()
        yield session
    finally:
        session.shutdown()


def chunk_strategies(strategies: list, batch_size: int) -> list[list]:
    """Split strategy list into batches capped at DEFAULT_BRIDGE_BATCH_MAX."""
    from blockchecks.engine.services.batch_probe import BatchScheduler

    return BatchScheduler(batch_size).iter_batches(strategies)
