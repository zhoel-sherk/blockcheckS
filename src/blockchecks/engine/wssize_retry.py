"""Unified wssize companion retry policy (ARC-4 / ARC-6)."""

from __future__ import annotations

from dataclasses import dataclass

WSSIZE_CMD = "wssize:wsize=1:scale=6"
WSSIZE_TIMEOUT_CAP = 1.5


@dataclass(frozen=True, slots=True)
class WssizeRetryPolicy:
    """When to retry TLS 1.2 FAIL with wssize companion and with what timeout."""

    cmd: str = WSSIZE_CMD
    timeout_cap: float = WSSIZE_TIMEOUT_CAP

    def retry_timeout(self, timeout: float) -> float:
        return min(timeout, self.timeout_cap)

    def should_retry(
        self,
        data: dict,
        *,
        try_wssize: bool,
        protocol: str,
        strategy: str,
        is_config: bool = False,
    ) -> bool:
        return (
            not data.get("success")
            and try_wssize
            and protocol == "tls12"
            and not is_config
            and "wssize" not in strategy
        )


WSSIZE_RETRY = WssizeRetryPolicy()
