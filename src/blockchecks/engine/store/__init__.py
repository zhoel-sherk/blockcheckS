"""Run state store public API."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from blockchecks.engine.paths import DEFAULT_DB_PATH, expand_path
from blockchecks.engine.store.models import Checkpoint
from blockchecks.engine.store.sqlite_store import (
    SqliteRunStore,
    fingerprint_mismatch,
    matrix_fingerprint,
)


@runtime_checkable
class RunStateStore(Protocol):
    """High-level async DAO for scan/run persistence."""

    @property
    def path(self) -> Path: ...

    async def init(self) -> None: ...
    async def flush(self) -> None: ...
    async def close(self) -> None: ...
    async def ensure_strategy(self, name: str, proto: str, config_path: str, **kwargs: Any) -> int: ...
    async def log_tcp(self, strategy: str, domain: str, status: str, latency_ms: float, **kwargs: Any) -> None: ...
    async def log_udp(
        self, strategy: str, target: str, status: str, latency_ms: float = 0, **kwargs: Any
    ) -> None: ...
    async def write_dns_audit_log(
        self, domain: str, udp_ips: str, doh_ips: str, verdict: str,
        doh_server: str = "", timestamp: str = "",
    ) -> None: ...
    async def log_pair(
        self,
        tcp: str,
        udp: str,
        domain: str,
        tcp_ok: bool,
        gateway_ok: bool,
        udp_ok: bool,
        tcp_ms: float,
        gateway_ms: float,
        udp_ms: float,
        overall: str,
    ) -> None: ...
    async def save_checkpoint(
        self,
        tcp_idx: int,
        udp_idx: int,
        note: str = "",
        fingerprint: str = "",
        tcp_label: str = "",
        udp_label: str = "",
    ) -> None: ...
    async def latest_checkpoint(self) -> Checkpoint | None: ...
    async def domain_pass_stats(
        self, domain: str, *, protos: tuple[str, ...] = ("tcp",)
    ) -> dict[str, int]: ...
    async def count_tcp_passes(self, domain: str | None = None) -> int: ...
    async def get_working_tcp(self, domain: str) -> list[str]: ...
    async def get_working_quic(self, domain: str) -> list[str]: ...
    async def get_working_proto(self, domain: str, proto: str) -> list[str]: ...
    async def get_working_tcp_details(self, domain: str) -> list[dict]: ...
    async def get_working_proto_details(self, domain: str, proto: str) -> list[dict]: ...
    async def get_completed_pair_keys(self, domain: str) -> set[tuple[str, str]]: ...
    async def has_tcp_result(self, strategy: str, domain: str, proto: str = "tcp") -> bool: ...
    async def get_completed_tcp_keys(self, proto: str = "tcp") -> set[tuple[str, str]]: ...
    async def get_best_tcp(self, domain: str, *, limit: int = 5) -> list[dict]: ...
    async def get_best_quic(self, domain: str, *, limit: int = 5) -> list[dict]: ...
    async def get_best_udp(self, *, limit: int = 5) -> list[dict]: ...
    async def get_best_pairs(self, domain: str, *, limit: int = 10) -> list[dict]: ...
    async def coverage_score(self, strategy: str) -> dict: ...
    async def get_best_by_coverage(self, *, limit: int = 5) -> list[dict]: ...
    async def get_common_tcp(self, domains: list[str], *, limit: int = 5) -> list[dict]: ...
    async def get_strategy_config(self, name: str, proto: str = "tcp") -> str | None: ...
    async def load_scan_weights(self) -> list[tuple[str, float]]: ...
    async def save_scan_weights(self, rows: list[tuple[str, float]]) -> None: ...


DEFAULT_DB_BATCH = 500


def open_run_store(
    db_path: str | Path | None = None,
    *,
    batch_size: int = 0,
) -> SqliteRunStore:
    """Open the default SQLite run state store."""
    path = expand_path(db_path, default=DEFAULT_DB_PATH)
    return SqliteRunStore(path, batch_size=batch_size)


__all__ = [
    "Checkpoint",
    "RunStateStore",
    "SqliteRunStore",
    "StateDB",
    "fingerprint_mismatch",
    "matrix_fingerprint",
    "open_run_store",
    "DEFAULT_DB_BATCH",
]

StateDB: type[SqliteRunStore] = SqliteRunStore  # backward compat alias
