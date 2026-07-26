"""Strategy loader — reads strategies from inline strings, files, or custom lists."""

from pathlib import Path
from typing import Optional


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
                strategies.append(line)
        return strategies

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
