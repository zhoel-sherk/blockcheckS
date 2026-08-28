"""Chunk strategies into lua-bridge batch windows."""

from __future__ import annotations

from typing import TYPE_CHECKING

from blockchecks.engine.config import DEFAULT_BRIDGE_BATCH_MAX

if TYPE_CHECKING:
    from blockchecks.engine.adaptive_queue import AdaptiveJob
    from blockchecks.engine.generators.base import StrategyItem


def batch_job_key(job: AdaptiveJob) -> tuple[str, str, str]:
    """Accumulator dedup key: (label, domain, protocol).

    Protocol comes from ``job.item.protocol`` (tls12, tls13, http, quic,
    udp_voice, …). Jobs with different protocols must not share one bridge
    batch — nfqws2 filters and probe transport differ per protocol.
    """
    proto = getattr(job.item, "protocol", None) or "tls12"
    return (job.item.label, job.domain, proto)


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
    """AQ bridge mode: accumulate jobs until batch_size unique batch keys.

    Key is ``(label, domain, protocol)`` — see :func:`batch_job_key`. The bridge
    is domain-agnostic (netns iptables redirects traffic to nfqws2; strategy
    selected by published id), so jobs from *different* domains can share one
    batch when protocol matches. Fan-out waves are excluded (classic per-strategy).
    """

    def __init__(self, batch_size: int) -> None:
        self.batch_size = max(1, batch_size)
        self._jobs: list[AdaptiveJob] = []
        self._keys: set[tuple[str, str, str]] = set()

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
        key = batch_job_key(job)
        if key in self._keys:
            return False
        if self._jobs and batch_job_key(self._jobs[0])[-1] != key[-1]:
            return False
        return len(self._jobs) < self.batch_size

    def push(self, job: AdaptiveJob) -> bool:
        if not self.can_accept(job):
            return False
        self._jobs.append(job)
        self._keys.add(batch_job_key(job))
        return True

    def is_full(self) -> bool:
        return len(self._jobs) >= self.batch_size
