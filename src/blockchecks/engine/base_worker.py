"""Probe worker lifecycle: setup, apply strategy, execute, collect, teardown."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


@dataclass
class WorkerContext:
    """Everything a worker needs to run one probe."""

    ns_name: str | None = None
    python_bin: str | None = None
    resolved_ip: str | None = None
    timeout: float = 5.0
    extra: dict[str, Any] = field(default_factory=dict)


class Worker(abc.ABC):
    """Lifecycle contract for a single probe execution."""

    @abc.abstractmethod
    def setup_environment(self, ctx: WorkerContext) -> None:
        """Prepare the namespace / tools / deps before the probe."""

    @abc.abstractmethod
    def apply_strategy(self, ctx: WorkerContext) -> None:
        """Start nfqws2 with the strategy / conf inside the environment."""

    @abc.abstractmethod
    def execute_probe(self, ctx: WorkerContext) -> dict:
        """Run the actual probe; return a JSON-serializable result dict."""

    @abc.abstractmethod
    def collect_metrics(self, ctx: WorkerContext, result: dict) -> dict:
        """Augment the result with timing / rss / error fields."""

    @abc.abstractmethod
    def teardown(self, ctx: WorkerContext) -> None:
        """Release netns / processes / fds; must be idempotent + safe on error."""

    # Convenience

    def run(self, ctx: WorkerContext) -> dict:
        """Full lifecycle in one call; teardown always runs (even on error)."""
        try:
            self.setup_environment(ctx)
            self.apply_strategy(ctx)
            result = self.execute_probe(ctx)
            return self.collect_metrics(ctx, result)
        finally:
            self.teardown(ctx)


class BaseInNsWorker(Worker):
    """Base for netns probe workers with a no-op teardown.

    Concrete workers override only the steps they need; ``collect_metrics``
    defaults to a passthrough.
    """

    def setup_environment(self, _ctx: WorkerContext) -> None:
        return None

    def apply_strategy(self, _ctx: WorkerContext) -> None:
        return None

    def collect_metrics(self, _ctx: WorkerContext, result: dict) -> dict:
        return result

    def teardown(self, _ctx: WorkerContext) -> None:
        return None
