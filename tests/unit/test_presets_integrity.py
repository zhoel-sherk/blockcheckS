"""Preset integrity: manifest completeness + strategy-line parseability."""

from __future__ import annotations

from pathlib import Path

import pytest
import tomllib

from blockchecks.engine.conf_builder import sanitize_arg_for_conf, split_cli_args
from blockchecks.engine.strategy_loader import StrategyLoader

PROJECT_DIR = Path(__file__).resolve().parents[2]
STRATEGIES_DIR = PROJECT_DIR / "presets" / "strategies"
DOMAINS_DIR = PROJECT_DIR / "presets" / "domains"
MANIFEST = PROJECT_DIR / "presets" / "manifest.toml"


def _load_manifest() -> dict:
    with MANIFEST.open("rb") as f:
        return tomllib.load(f)


def _nonempty_lines(path: Path) -> list[str]:
    """Strategy lines (strip comments / blanks), like StrategyLoader.from_file."""
    return [
        ln.strip()
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]


@pytest.mark.unit
def test_manifest_exists_and_valid_toml():
    data = _load_manifest()
    assert data["version"] == 1
    assert isinstance(data["strategies"], dict)
    assert isinstance(data["domains"], dict)
    assert len(data["strategies"]) >= 10
    assert len(data["domains"]) >= 5


@pytest.mark.unit
def test_manifest_covers_all_strategy_files():
    data = _load_manifest()
    manifest_files = {v["file"] for v in data["strategies"].values()}
    actual = {p.name for p in STRATEGIES_DIR.glob("*.tls")}
    actual |= {p.name for p in STRATEGIES_DIR.glob("*.txt")}
    actual |= {p.name for p in STRATEGIES_DIR.glob("*.http")}
    actual |= {p.name for p in STRATEGIES_DIR.glob("*.quic")}
    actual |= {p.name for p in STRATEGIES_DIR.glob("*.udp")}
    assert manifest_files == actual, (
        f"manifest mismatch: only-in-manifest={manifest_files - actual}, "
        f"only-on-disk={actual - manifest_files}"
    )
    for entry in data["strategies"].values():
        assert (STRATEGIES_DIR / entry["file"]).is_file(), entry["file"]


@pytest.mark.unit
def test_manifest_covers_all_domain_files():
    data = _load_manifest()
    manifest_files = {v["file"] for v in data["domains"].values()}
    actual = {p.name for p in DOMAINS_DIR.glob("*.txt")}
    assert manifest_files == actual, (
        f"domain manifest mismatch: only-in-manifest={manifest_files - actual}, "
        f"only-on-disk={actual - manifest_files}"
    )
    for entry in data["domains"].values():
        assert (DOMAINS_DIR / entry["file"]).is_file(), entry["file"]


@pytest.mark.unit
@pytest.mark.parametrize(
    "path",
    sorted(STRATEGIES_DIR.glob("*.tls"))
    + sorted(STRATEGIES_DIR.glob("*.txt"))
    + sorted(STRATEGIES_DIR.glob("*.http"))
    + sorted(STRATEGIES_DIR.glob("*.quic"))
    + sorted(STRATEGIES_DIR.glob("*.udp")),
    ids=lambda p: p.name,
)
def test_every_strategy_line_parses(path: Path):
    """Every non-comment line must parse via the shared nfqws2 CLI splitter."""
    lines = _nonempty_lines(path)
    assert lines, f"{path.name} has no strategy lines"
    for line in lines:
        # Lines are lua-desync specs OR full CLI fragments. Both must survive
        # the shared sanitizer (no bare '<', balanced tokens) without raising.
        parts = split_cli_args(line)
        for part in parts:
            assert part.startswith("--")
            sanitize_arg_for_conf(part)
        # A full CLI fragment starting with -- must carry only valid nfqws2
        # flags; a bare spec (no leading --) is wrapped as lua-desync.
        if line.startswith("--"):
            assert all(p.startswith("--") for p in split_cli_args(line))


@pytest.mark.unit
def test_strategy_loader_reads_every_preset():
    """StrategyLoader.from_file (the runtime reader) accepts every preset."""
    for path in list(STRATEGIES_DIR.glob("*.tls")) + list(STRATEGIES_DIR.glob("*.txt")):
        loaded = StrategyLoader.from_file(str(path))
        assert loaded, f"{path.name} loaded empty"


@pytest.mark.unit
def test_manifest_domain_counts_match_files():
    data = _load_manifest()
    for entry in data["domains"].values():
        path = DOMAINS_DIR / entry["file"]
        nonempty = _nonempty_lines(path)
        assert len(nonempty) == entry["count"], (
            f"{entry['file']}: manifest count={entry['count']}, actual={len(nonempty)}"
        )


@pytest.mark.unit
def test_denylist_not_selectable():
    from blockchecks.engine.preset_paths import PresetPathError, resolve_domain_preset

    with pytest.raises(PresetPathError):
        resolve_domain_preset("denylist")
