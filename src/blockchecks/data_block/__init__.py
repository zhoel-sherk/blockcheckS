"""data_block integration — per-provider DNS cache, pass strategies, configs.

``data_block/`` is a git submodule (https://github.com/zhoel-sherk/data_block)
mounted inside the blockcheckS repo.  Files are written to
``data_block/providers/<provider>/``; a git commit/push happens only when the
``--data-block-sync`` flag is passed (no automatic GitHub writes at runtime).
"""

from __future__ import annotations

from blockchecks.data_block.provider import (
    DEFAULT_PROVIDER,
    get_provider_dir,
    provider_name,
)
from blockchecks.data_block.store import (
    DATA_BLOCK_DNS_TTL,
    ProviderStore,
    write_best_config,
    write_hosts_file,
)

__all__ = [
    "DATA_BLOCK_DNS_TTL",
    "DEFAULT_PROVIDER",
    "ProviderStore",
    "get_provider_dir",
    "provider_name",
    "write_best_config",
    "write_hosts_file",
]
