"""Batch scheduling — chunk strategies/jobs into bridge-sized batches."""

from __future__ import annotations

from typing import TYPE_CHECKING

from blockchecks.engine.config import DEFAULT_BRIDGE_BATCH_MAX

if TYPE_CHECKING:
    from blockchecks.engine.adaptive_queue import AdaptiveJob
    from blockchecks.engine.generators.base import StrategyItem


class BatchScheduler:
    """Chunk strategies/jobs into bridge-sized batches."""

    def __init__(self, batch_size: int) -> None:
        self.batch_size = max(1, min(batch_size, DEFAULT_BRIDGE_BATCH_MAX))

    def iter_batches(self, items: list[StrategyItem]) -> list[list[StrategyItem]]:
        n = self.batch_size
        if not items:
            return []
        return [items[i : i + n] for i in range(0, len(items), n)]

    def group_jobs_by_domain(
        self,
        jobs: list[AdaptiveJob],
        *,
        flush_partial: bool = True,
    ) -> list[list[AdaptiveJob]]:
        """Group consecutive jobs with same domain into batches up to batch_size."""
        if not jobs:
            return []
        out: list[list[AdaptiveJob]] = []
        cur_domain = jobs[0].domain
        cur: list[AdaptiveJob] = []
        labels: set[str] = set()

        for job in jobs:
            if job.domain != cur_domain:
                if cur:
                    out.append(cur)
                cur = []
                labels = set()
                cur_domain = job.domain
            if job.item.label in labels:
                if cur:
                    out.append(cur)
                cur = [job]
                labels = {job.item.label}
                continue
            if len(cur) >= self.batch_size:
                out.append(cur)
                cur = []
                labels = set()
            cur.append(job)
            labels.add(job.item.label)

        if cur and (flush_partial or len(cur) >= self.batch_size):
            out.append(cur)
        return out


class BatchJobAccumulator:
    """AQ bridge mode: accumulate jobs until batch_size unique (label, domain) keys.

    The bridge is domain-agnostic (netns iptables redirects all :443 traffic to
    nfqws2; strategy selected by published id), so jobs from *different* domains
    can share one batch. Only fan-out waves are excluded (classic per-strategy).
    """

    def __init__(self, batch_size: int) -> None:
        self.batch_size = max(1, batch_size)
        self._jobs: list[AdaptiveJob] = []
        self._keys: set[tuple[str, str]] = set()

    def __len__(self) -> int:
        return len(self._jobs)

    @property
    def domain(self) -> str | None:
        return self._jobs[0].domain if self._jobs else None

    @property
    def domains(self) -> list[str]:
        return [j.domain for j in self._jobs]

    def flush(self) -> list[AdaptiveJob]:
        jobs = self._jobs
        self._jobs = []
        self._keys = set()
        return jobs

    def can_accept(self, job: AdaptiveJob) -> bool:
        if job.fanout:
            return False
        if job.key in self._keys:
            return False
        return len(self._jobs) < self.batch_size

    def push(self, job: AdaptiveJob) -> bool:
        if not self.can_accept(job):
            return False
        self._jobs.append(job)
        self._keys.add(job.key)
        return True

    def is_full(self) -> bool:
        return len(self._jobs) >= self.batch_size
