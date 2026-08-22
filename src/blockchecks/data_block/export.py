"""Copy XDG provider store into a git data_block checkout (pip-safe)."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from blockchecks.data_block.provider import (
    data_block_repo_root,
    provider_name,
)
from blockchecks.data_block.store import ProviderStore
from blockchecks.engine.paths import reclaim_sudo_ownership

log = logging.getLogger(__name__)

CLONE_HINT = (
    "data_block is a git submodule, not shipped in the wheel. "
    "git clone https://github.com/zhoel-sherk/data_block.git "
    "&& bs data-block --out ./data_block"
)

_SKIP_SUFFIXES = ("-wal", "-shm", "-journal")


def default_export_dest() -> Path | None:
    """Submodule/checkout with ``.git``, else None (pip users must pass --out)."""
    root = data_block_repo_root()
    if root is None:
        return None
    if (root / ".git").exists():
        return root
    return None


def export_runtime_data_block(out: Path, *, provider: str | None = None) -> int:
    """Copy XDG ``providers/`` into *out*/providers/. Other dest slugs are kept.

    Returns the number of provider directories copied.
    """
    from blockchecks.data_block import provider as prov

    src_base = prov.data_block_runtime_root() / "providers"
    dest_base = Path(out).expanduser().resolve() / "providers"
    dest_base.mkdir(parents=True, exist_ok=True)
    reclaim_sudo_ownership(dest_base)
    if not src_base.is_dir():
        log.warning("%s", f"  WARNING: no XDG providers at {src_base}")
        return 0
    slugs = [provider] if provider else sorted(p.name for p in src_base.iterdir() if p.is_dir())
    copied = 0
    for slug in slugs:
        src = src_base / slug
        if not src.is_dir():
            log.warning("%s", f"  WARNING: provider {slug} not in XDG store")
            continue
        dest = dest_base / slug
        dest.mkdir(parents=True, exist_ok=True)
        for item in src.iterdir():
            if item.name.endswith(_SKIP_SUFFIXES):
                continue
            if not item.is_file():
                continue
            target = dest / item.name
            tmp = target.with_name(target.name + ".tmp")
            shutil.copy2(item, tmp)
            tmp.replace(target)
            reclaim_sudo_ownership(target)
        reclaim_sudo_ownership(dest)
        copied += 1
        log.info("%s", f"  [data_block] exported {slug} → {dest}")
    return copied


def sync_exported(out: Path, *, push: bool = True) -> bool:
    slug = provider_name(allow_detect=False)
    store = ProviderStore(Path(out) / "providers" / slug)
    return store.sync_commit(push=push, repo_root=Path(out))
