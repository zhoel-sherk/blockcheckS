"""Load strategies from an inline string, a file, or a config directory."""

from __future__ import annotations

import logging
from pathlib import Path

from blockchecks.engine.static_validator import validate_strategy

log = logging.getLogger(__name__)


class StrategyLoader:
    """Load DPI bypass strategies from various sources."""

    @staticmethod
    def from_string(strategy: str) -> list[str]:
        """Parse a single strategy string (e.g., 'fake:repeats=6:tcp_ts=-1000')."""
        s = strategy.strip()
        return [s] if s else []

    @staticmethod
    def from_file(path: str) -> list[str]:
        """Load strategies from a text file (one per line, # comments)."""
        strategies = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                strategies.append(line.replace("\\n", "\n"))
        return strategies

    @staticmethod
    def from_config_dir(config_dir: str) -> list[str]:
        """Load nfqws2 .conf files from a directory (sorted by name)."""
        configs = sorted(Path(config_dir).glob("*.conf"))
        return [str(c) for c in configs]

    @staticmethod
    def from_config(path: str) -> list[str]:
        """Load a single .conf file (returns as single-element list)."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config not found: {p}")

        try:
            text = p.read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("config file unreadable %s: %s", p, exc)
            return [str(p)]

        if not text.strip():
            log.warning("config file is empty: %s", p)
            return [str(p)]

        desyncs = [
            line.split("=", 1)[1].strip()
            for raw in text.splitlines()
            if (line := raw.strip()).startswith("--lua-desync=")
        ]
        if not desyncs:
            log.warning("config has no --lua-desync lines: %s", p)
        for desync in desyncs:
            if not desync:
                continue
            errors = (
                i for i in validate_strategy(desync).issues if i.severity == "error"
            )
            for issue in errors:
                log.warning(
                    "config %s lua-desync validation (%s): %s",
                    p,
                    issue.code,
                    issue.message,
                )

        return [str(p)]

    @staticmethod
    def from_custom_dir(test_dir: str, protocol: str) -> list[str]:
        """Load strategies from blockcheck2.d/custom/<list_file>.

        Args:
            test_dir: path to blockcheck2.d directory (e.g., '/opt/zapret2/blockcheck2.d')
            protocol: 'http', 'tls12', 'tls13', 'quic', or 'udp_voice'
        """
        file_map = {
            "http": "list_http.txt",
            "tls12": "list_https_tls12.txt",
            "tls13": "list_https_tls13.txt",
            "quic": "list_quic.txt",
            "udp_voice": "list_udp_voice.txt",
        }
        filename = file_map.get(protocol)
        if not filename:
            raise ValueError(f"Unknown protocol: {protocol}")

        filepath = Path(test_dir) / "custom" / filename
        if not filepath.exists():
            raise FileNotFoundError(f"Strategy file not found: {filepath}")

        return StrategyLoader.from_file(str(filepath))
