"""Load strategies from custom lists, config files, and a user matrix file."""

import logging
import os
import sys

from blockchecks.engine.generators.base import StrategyGenerator, StrategyItem
from blockchecks.engine.store import RunStateStore

log = logging.getLogger(__name__)


class CustomListGenerator(StrategyGenerator):
    """Load strategies from blockcheck2.d/custom/list_*.txt files."""

    FILE_MAP = {
        "http": "list_http.txt",
        "tls12": "list_https_tls12.txt",
        "tls13": "list_https_tls13.txt",
        "quic": "list_quic.txt",
        "udp_voice": "list_udp_voice.txt",
    }

    def __init__(self, base_dir: str = "/opt/zapret2/blockcheck2.d/custom"):
        self.base_dir = base_dir

    async def generate(
        self,
        protocol: str = "tls12",
        state_db: RunStateStore = None,
        domain: str = "",
        scan_level: str = "fast",
        max_count: int = 100,
        run_set: set = None,
    ) -> list[StrategyItem]:
        filename = self.FILE_MAP.get(protocol)
        if not filename:
            return []

        path = os.path.join(self.base_dir, filename)
        if not os.path.exists(path):
            return []

        items = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                label = line.replace(" ", "_").replace(":", "_")
                proto = {
                    "http": "http",
                    "quic": "quic",
                    "tls13": "tls13",
                    "udp_voice": "udp_voice",
                }.get(protocol, "tls12")
                items.append(StrategyItem(label=label, strategy=line, protocol=proto))
                if scan_level == "single" and items:
                    break
        return items[:max_count]


class ConfigFileGenerator(StrategyGenerator):
    """Load pre-built .conf files."""

    def __init__(self, config_dir: str = None):
        from blockchecks.engine.config import CONFIGS_DIR

        self.config_dir = config_dir or CONFIGS_DIR

    @staticmethod
    def _desync_text(path: str) -> str:
        """Extract concatenated --lua-desync payload from a .conf file."""
        out: list[str] = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if line.startswith("--lua-desync="):
                    out.append(line[len("--lua-desync=") :])
        return "\n".join(out)

    def _validate_or_skip(self, path: str, label: str) -> bool:
        """Static-validate the config payload; skip (loudly) on errors.

        A config referencing an unresolvable blob dies per-packet inside
        nfqws2: the strategy is never applied but probes still hit the wire
        clean — producing false "PASS without APPLIED" rows. Skipping here
        keeps the matrix honest.
        """
        from blockchecks.engine.static_validator import validate_strategy

        text = self._desync_text(path)
        if not text:
            return True  # no lua-desync payload; nothing to validate here
        result = validate_strategy(text)
        errors = [i for i in result.issues if i.severity == "error"]
        if not errors:
            return True
        details = "; ".join(f"{i.code}: {i.message}" for i in errors)
        log.warning(
            "%s",
            f"  WARNING: config {label!r} skipped — static validation failed ({details})",
        )
        return False

    async def generate(
        self,
        protocol: str = "tls12",
        state_db: RunStateStore = None,
        domain: str = "",
        scan_level: str = "fast",
        max_count: int = 100,
        run_set: set = None,
    ) -> list[StrategyItem]:
        if not os.path.isdir(self.config_dir):
            return []

        items = []
        filter_term = "udp_voice" if protocol == "udp_voice" else None
        for fname in sorted(os.listdir(self.config_dir)):
            if not fname.endswith(".conf"):
                continue
            if filter_term and filter_term not in fname:
                continue
            if not filter_term and "udp_voice" in fname:
                continue
            path = os.path.join(self.config_dir, fname)
            label = fname.replace(".conf", "")
            if not self._validate_or_skip(path, label):
                continue
            items.append(StrategyItem(label=label, strategy=path, is_config=True))
            if scan_level == "single" and items:
                break
        return items[:max_count]


_UDP_SKIP_TCP_CLI = ("--filter-tcp", "--qnum=200")
_UDP_SKIP_ON_TCP = (
    "--filter-udp",
    "--qnum=201",
    "filter-udp",
    "blob=discord_udp",
    "discord_ip_discovery",
)


class UserMatrixGenerator(StrategyGenerator):
    """Load strategies from user-provided file (one per line).

    ``-`` reads from stdin (piped matrix).  A literal ``\\n`` sequence in a
    line becomes a real newline so multi-desync / CLI companion strategies fit
    on one matrix line.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath

    async def generate(
        self,
        protocol: str = "tls12",
        state_db: RunStateStore = None,
        domain: str = "",
        scan_level: str = "fast",
        max_count: int = 100,
        run_set: set = None,
    ) -> list[StrategyItem]:
        if self.filepath == "-":
            lines = sys.stdin.read().splitlines()
        else:
            if not os.path.exists(self.filepath):
                log.info("%s", f"[matrix] User matrix file not found: {self.filepath}")
                return []
            with open(self.filepath) as f:
                lines = f.read().splitlines()

        items = []
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#") or line == "---":
                continue
            strategy = line.replace("\\n", "\n")
            low = strategy.lower()
            if protocol != "udp_voice" and any(kw in low for kw in _UDP_SKIP_ON_TCP):
                continue
            if protocol == "udp_voice" and any(tok in low for tok in _UDP_SKIP_TCP_CLI):
                continue
            label = strategy.split("\n", 1)[0].replace(" ", "_").replace(":", "_")
            items.append(StrategyItem(label=label, strategy=strategy, protocol=protocol))
            if scan_level == "single" and items:
                break
        return items[:max_count]
