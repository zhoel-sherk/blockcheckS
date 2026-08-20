"""Per-provider DNS cache, pass strategies, and configs under data_block/providers/<name>/."""

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
