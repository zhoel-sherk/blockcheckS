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
