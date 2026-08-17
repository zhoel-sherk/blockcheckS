"""nfqws2 Lua bridge — /dev/shm file IPC (strategy.id/gen + events.ndjson)."""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from blockchecks.engine.config import SHM_BASE


@dataclass(frozen=True)
class BridgeEvent:
    event: str
    gen: int = 0
    id: int = 0
    reason: str = ""
    ttl: int = 0
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
            raw=data,
        )

    def is_rst_in(self) -> bool:
        """True if this event is a DPI-injected inbound RST (scan_bridge)."""
        return self.event == "STRATEGY_FAIL" and self.reason == "rst_in"

    def to_dict(self) -> dict:
        """Serializable dict for API/SSE consumers (mirrors vars())."""
        return {
            "event": self.event,
            "gen": self.gen,
            "id": self.id,
            "reason": self.reason,
            "ttl": self.ttl,
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
        os.chmod(self.paths.base, 0o777)
        self._init_events()

    def _init_events(self) -> None:
        # nfqws2 drops privileges (setuid nobody/overflow) after init and must
        # be able to APPEND APPLIED/STRATEGY_FAIL events. The file is created
        # by Python as root — make it world-writable or Lua's io.open("a")
        # returns nil and the strategy-selection events are silently lost.
        self.paths.events.write_text("", encoding="utf-8")
        os.chmod(self.paths.events, 0o666)

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
                os.chmod(self.paths.base / name, 0o666)

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
        self._init_events()
