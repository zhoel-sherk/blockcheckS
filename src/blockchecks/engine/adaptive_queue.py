"""Online job queue for full/scan: epsilon-greedy priority, family/cluster weights, sibling expansion."""

from __future__ import annotations

import heapq
import random
import re
import time
from dataclasses import dataclass, field
from functools import cache
from typing import TYPE_CHECKING

from blockchecks.engine.family_needs import classify_strategy_family

if TYPE_CHECKING:
    from blockchecks.engine.generators.base import StrategyItem

# Domain clusters

CLUSTER_DISCORD = "discord"
CLUSTER_GOOGLE = "google"
CLUSTER_YOUTUBE = "youtube"
CLUSTER_GENERAL = "general"

_DISCORD_RE = re.compile(r"discord|discordapp|discord\.gg|discord\.media", re.I)
_GOOGLE_RE = re.compile(r"google|gstatic|googleapis|ggpht|googleusercontent", re.I)
_YOUTUBE_RE = re.compile(r"youtube|googlevideo|ytimg|youtu\.be", re.I)


def cluster_domain(domain: str) -> str:
    """Map FQDN to coarse cluster (AQ3)."""
    d = domain.lower().split("/")[0].strip(".")
    if _DISCORD_RE.search(d):
        return CLUSTER_DISCORD
    if _YOUTUBE_RE.search(d):
        return CLUSTER_YOUTUBE
    if _GOOGLE_RE.search(d):
        return CLUSTER_GOOGLE
    return CLUSTER_GENERAL


def sibling_domains(domain: str, all_domains: list[str]) -> list[str]:
    """Same-cluster domains except *domain* (AQ2)."""
    cluster = cluster_domain(domain)
    return [d for d in all_domains if d != domain and cluster_domain(d) == cluster]


@cache
def extract_blob_hints(strategy: str) -> tuple[str, ...]:
    """Blob aliases referenced in a strategy string (cached, immutable tuple)."""
    hints: list[str] = []
    for m in re.finditer(r"blob=([a-zA-Z0-9_]+)", strategy):
        name = m.group(1)
        if name not in hints:
            hints.append(name)
    return tuple(hints)


@cache
def strategy_traits(strategy: str) -> tuple[str, ...]:
    """Strategy-genetics traits: repeats / fooling / ttl / pos.

    Extracts coarse axes from the strategy string so a PASS on
    ``fake:blob=stun:repeats=6:ttl=127`` boosts sibling strategies that share
    ``repeats=6``, the same fooling kind or TTL family — Geneva-style
    "genetically close" evolution, decoupled from the target domain.
    """
    traits: list[str] = []
    add = lambda v: traits.append(v) if v not in traits else None  # noqa: E731

    for m in re.finditer(r"repeats=(\d+)", strategy):
        add(f"r{m.group(1)}")
    for m in re.finditer(
        r"(tcp_ts|tcp_md5|badsid|badseq|badsum|seqovl|ip_ttl|tcp_seq|tcp_ack)", strategy
    ):
        add(f"fool:{m.group(1)}")
    for m in re.finditer(r"ttl=(\d+)", strategy):
        t = int(m.group(1))
        bucket = 1 if t <= 8 else 2 if t <= 32 else 3 if t <= 128 else 4
        add(f"ttl{bucket}")
    for m in re.finditer(r"pos=([A-Za-z0-9_,]+)", strategy):
        add(f"pos:{m.group(1)}")
    for m in re.finditer(r"ip_ttl=(\d+)", strategy):
        add(f"ipttl{m.group(1)}")
    # desync technique family names embedded in the strategy string
    for m in re.finditer(
        r"(hostfakesplit|fakedsplit|fakeddisorder|multisplit|multidisorder|"
        r"tlsrec|oob|syndata|pktmod|send|dupfake)",
        strategy,
    ):
        add(f"tec:{m.group(1)}")
    return tuple(traits)


# Runtime metrics


@dataclass
class AdaptiveMetrics:
    """Collected during an adaptive scan run."""

    total_enqueued: int = 0
    jobs_run: int = 0
    jobs_passed: int = 0
    fanout_enqueued: int = 0
    started_at: float = field(default_factory=time.monotonic)
    first_pass_at: float | None = None
    passes_before_half: int = 0
    half_mark_jobs: int = 0

    def record_run(self, *, passed: bool) -> None:
        self.jobs_run += 1
        if passed:
            self.jobs_passed += 1
            now = time.monotonic()
            if self.first_pass_at is None:
                self.first_pass_at = now - self.started_at
            if self.half_mark_jobs and self.jobs_run <= self.half_mark_jobs:
                self.passes_before_half += 1

    def set_half_mark(self, total: int) -> None:
        self.half_mark_jobs = max(1, total // 2)

    @property
    def time_to_first_pass(self) -> float | None:
        return self.first_pass_at

    @property
    def pass_rate_before_half(self) -> float:
        if not self.half_mark_jobs:
            return 0.0
        return self.passes_before_half / max(1, min(self.jobs_run, self.half_mark_jobs))


# Weight table

_MAX_WEIGHT = 64.0

_SPLIT_POS_TRAITS = {
    "first_byte": "pos:1",
    "sni_marker": "pos:sniext+1",
    "seqovl": "fool:seqovl",
}


@dataclass
class ScanWeights:
    """In-memory strategy-genetics weights (persisted via StateDB).

    Works on the *strategy* genetics, not domains: a PASS on
    ``fake:blob=stun:repeats=6`` boosts the family (``fake``), the blob
    (``stun``) and the repeat/fooling/ttl traits, so sibling strategies of the
    same genetics are tested next regardless of which domain they target.
    Cluster (domain) weights were removed — domain must not bias strategy
    priority, and 4 parallel netns must isolate domains (no all-youtube).
    """

    family: dict[str, float] = field(default_factory=dict)
    blob: dict[str, float] = field(default_factory=dict)
    trait: dict[str, float] = field(default_factory=dict)  # repeats/fooling/ttl/pos
    family_boost: float = 1.0
    blob_boost: float = 0.5
    trait_boost: float = 0.4
    #: Strategy keys already boosted from provider pass_strategies this process.
    _provider_boosted: set[str] = field(default_factory=set, repr=False, compare=False)

    _TRIAGE_FAMILY_SEED = 2.0
    _TRIAGE_FOOL_SEED = 0.8
    _TRIAGE_BLOB_SEED = 0.5
    _TRIAGE_POS_SEED = 0.4

    def seed_from_triage(self, profile) -> None:
        """Cold-start family/blob/trait weights from a preflight TriageProfile.

        Idempotent across resume: persisted or prior seeds are not re-multiplied;
        new keys get a one-time capped seed (max 64, same as boost_pass).
        """
        if profile is None:
            return
        from blockchecks.engine.blob_filter import aliases_for_class
        from blockchecks.engine.family_registry import dead_fooling_tokens, families_for_profile

        for fam in families_for_profile(profile):
            if fam not in self.family:
                self.family[fam] = min(self._TRIAGE_FAMILY_SEED, _MAX_WEIGHT)
            else:
                self.family[fam] = min(self.family[fam], _MAX_WEIGHT)
        for tok in dead_fooling_tokens(profile):
            self.trait[f"fool:{tok}"] = 0.1
        for fool in profile.viable_foolings:
            key = fool.split("=", 1)[0]
            trait_key = f"fool:{key}"
            if trait_key not in self.trait:
                self.trait[trait_key] = min(self._TRIAGE_FOOL_SEED, _MAX_WEIGHT)
            else:
                self.trait[trait_key] = min(self.trait[trait_key], _MAX_WEIGHT)
        for blob in profile.viable_blobs:
            if blob not in self.blob:
                self.blob[blob] = min(self._TRIAGE_BLOB_SEED, _MAX_WEIGHT)
            else:
                self.blob[blob] = min(self.blob[blob], _MAX_WEIGHT)
            for alias in aliases_for_class(blob):
                if alias not in self.blob:
                    self.blob[alias] = min(self._TRIAGE_BLOB_SEED, _MAX_WEIGHT)
                else:
                    self.blob[alias] = min(self.blob[alias], _MAX_WEIGHT)
        if profile.split_mode:
            trait_key = _SPLIT_POS_TRAITS.get(profile.split_mode, f"pos:{profile.split_mode}")
            if trait_key not in self.trait:
                self.trait[trait_key] = min(self._TRIAGE_POS_SEED, _MAX_WEIGHT)
            else:
                self.trait[trait_key] = min(self.trait[trait_key], _MAX_WEIGHT)

    def boost_provider_once(self, strategy_key: str, family: str, blobs: list[str], traits: list[str]) -> bool:
        """Apply provider preflight boost at most once per strategy per process."""
        if strategy_key in self._provider_boosted:
            return False
        self._provider_boosted.add(strategy_key)
        self.boost_pass(family, blobs, traits)
        return True

    def get(self, family: str, blobs: list[str], traits: list[str]) -> float:
        score = self.family.get(family, 1.0)
        for b in blobs:
            score += self.blob.get(b, 0.0)
        for t in traits:
            score += self.trait.get(t, 0.0)
        return score

    def boost_pass(
        self,
        family: str,
        blobs: list[str],
        traits: list[str],
    ) -> None:
        self.family[family] = min(self.family.get(family, 1.0) + self.family_boost, _MAX_WEIGHT)
        for b in blobs:
            self.blob[b] = min(self.blob.get(b, 0.0) + self.blob_boost, _MAX_WEIGHT)
        for t in traits:
            self.trait[t] = min(self.trait.get(t, 0.0) + self.trait_boost, _MAX_WEIGHT)

    def to_rows(self) -> list[tuple[str, float]]:
        rows: list[tuple[str, float]] = []
        for k, v in self.family.items():
            rows.append((f"family:{k}", v))
        for k, v in self.blob.items():
            rows.append((f"blob:{k}", v))
        for k, v in self.trait.items():
            rows.append((f"trait:{k}", v))
        return rows

    @classmethod
    def from_rows(cls, rows: list[tuple[str, float]]) -> ScanWeights:
        w = cls()
        for key, val in rows:
            if key.startswith("family:"):
                w.family[key[7:]] = val
            elif key.startswith("blob:"):
                w.blob[key[5:]] = val
            elif key.startswith("trait:"):
                w.trait[key[6:]] = val
        return w


# Priority queue plus epsilon-random


@dataclass(slots=True)
class AdaptiveJob:
    """One (strategy × domain) work unit.

    ``slots=True`` + lazy ``blobs``/``traits``/``key`` cut ~250 B/job (the
    blobs/traits lists are precomputed identically for every domain of the same
    strategy, so a single lru-cached tuple per strategy string is shared).
    """

    item: StrategyItem
    domain: str
    family: str = ""
    fanout: bool = False  # enqueued by sibling expansion
    _blobs: tuple[str, ...] | None = None
    _traits: tuple[str, ...] | None = None
    _key: tuple[str, str] | None = None

    @property
    def key(self) -> tuple[str, str]:
        k = self._key
        if k is None:
            k = (self.item.label, self.domain)
            self._key = k
        return k

    @property
    def blobs(self) -> tuple[str, ...]:
        b = self._blobs
        if b is None:
            b = extract_blob_hints(self.item.strategy)
            self._blobs = b
        return b

    @property
    def traits(self) -> tuple[str, ...]:
        t = self._traits
        if t is None:
            t = strategy_traits(self.item.strategy)
            self._traits = t
        return t

    @classmethod
    def from_item(cls, item: StrategyItem, domain: str, *, fanout: bool = False) -> AdaptiveJob:
        return cls(
            item=item,
            domain=domain,
            family=classify_strategy_family(item),
            fanout=fanout,
        )


@dataclass(order=True, slots=True)
class _HeapEntry:
    neg_priority: float
    seq: int
    key: tuple[str, str] = field(compare=False)


class AdaptiveJobQueue:
    """Priority heap with ε-greedy exploration (AQ1)."""

    def __init__(
        self,
        *,
        weights: ScanWeights | None = None,
        epsilon: float = 0.1,
        seed: int | None = None,
    ):
        self.weights = weights or ScanWeights()
        self.epsilon = max(0.0, min(1.0, epsilon))
        self._rng = random.Random(seed)
        self._seq = 0
        self._heap: list[_HeapEntry] = []
        self._pending: dict[tuple[str, str], AdaptiveJob] = {}
        self._done: set[tuple[str, str]] = set()
        self._all_domains: list[str] = []
        #: HARD exclusions (e.g. quarantined domains): jobs on these domains are
        #: dropped on pop and never enqueued by fan-out. Unlike the soft
        #: ``exclude_domains`` argument (other workers' active domains), hard
        #: exclusions never fall through the "everything excluded" fallback.
        self.excluded_domains: set[str] = set()
        self.metrics = AdaptiveMetrics()
        self._heap_rebuild_every: int = 0
        self._heap_rebuild_counter: int = 0

    def __len__(self) -> int:
        return len(self._pending)

    def enqueue(self, job: AdaptiveJob) -> bool:
        """Add job if not pending/done. Returns True if added."""
        if job.key in self._pending or job.key in self._done:
            return False
        priority = self.weights.get(job.family, job.blobs, job.traits)
        self._seq += 1
        self._pending[job.key] = job
        heapq.heappush(self._heap, _HeapEntry(-priority, self._seq, job.key))
        self.metrics.total_enqueued += 1
        return True

    def enqueue_many(self, jobs: list[AdaptiveJob]) -> int:
        return sum(1 for j in jobs if self.enqueue(j))

    def pop(self, exclude_domains: set[str] | None = None) -> AdaptiveJob | None:
        """Pop next job (highest priority or ε-random).

        ``exclude_domains`` — soft skip for jobs whose domain is already being
        probed by another worker (falls through to "any" when everything is
        excluded). ``self.excluded_domains`` — HARD: those jobs are dropped
        permanently (quarantine) and never returned, even by the fallback.
        """
        if not self._pending:
            return None
        exclude = set(exclude_domains or ()) | self.excluded_domains

        if self.epsilon > 0 and self._rng.random() < self.epsilon and len(self._pending) > 1:
            eligible = [k for k in self._pending if self._pending[k].domain not in exclude]
            if not eligible:
                eligible = [
                    k
                    for k in self._pending
                    if self._pending[k].domain not in self.excluded_domains
                ]
            if not eligible:
                return None
            key = self._rng.choice(eligible)
            return self._pending.pop(key)

        skipped: list[_HeapEntry] = []
        while self._heap:
            entry = heapq.heappop(self._heap)
            job = self._pending.get(entry.key)
            if job is None:
                continue
            if job.domain in self.excluded_domains:
                # Quarantined (or otherwise hard-excluded): discard forever.
                self._done.add(job.key)
                self._pending.pop(job.key)
                continue
            if job.domain in exclude:
                skipped.append(entry)
                continue
            self._pending.pop(entry.key)
            if skipped:
                for e in skipped:
                    heapq.heappush(self._heap, e)
            return job
        # everything soft-excluded — allow any pending job that is not hard-excluded
        while skipped:
            entry = heapq.heappop(skipped)
            job = self._pending.pop(entry.key, None)
            if job is not None:
                for e in skipped:
                    heapq.heappush(self._heap, e)
                return job
        return None

    def configure_heap_rebuild(self, every: int) -> None:
        """Rebuild priority heap every *every* mark_done calls (bridge mode)."""
        self._heap_rebuild_every = max(0, int(every))
        self._heap_rebuild_counter = 0

    def _maybe_rebuild_heap(self) -> None:
        if self._heap_rebuild_every <= 0:
            return
        self._heap_rebuild_counter += 1
        if self._heap_rebuild_counter >= self._heap_rebuild_every:
            self._rebuild_heap()
            self._heap_rebuild_counter = 0

    def mark_done(self, job: AdaptiveJob, *, passed: bool) -> int:
        """Mark job complete; on PASS boost strategy genetics + fan-out (AQ2/AQ4)."""
        self._done.add(job.key)
        self._pending.pop(job.key, None)
        self.metrics.record_run(passed=passed)
        if not passed:
            return 0
        self.weights.boost_pass(job.family, job.blobs, job.traits)
        self._maybe_rebuild_heap()
        return self.fanout_on_pass(job)

    def fanout_on_pass(self, job: AdaptiveJob) -> int:
        """Enqueue same strategy on sibling domains in the same cluster (AQ2)."""
        if not self._all_domains:
            return 0
        siblings = sibling_domains(job.domain, self._all_domains)
        added = 0
        for dom in siblings:
            if dom in self.excluded_domains:
                continue  # quarantined — never fan out
            fj = AdaptiveJob.from_item(job.item, dom, fanout=True)
            if self.enqueue(fj):
                added += 1
        self.metrics.fanout_enqueued += added
        return added

    def _rebuild_heap(self) -> None:
        self._heap = [
            _HeapEntry(
                -self.weights.get(job.family, job.blobs, job.traits),
                self._seq + i,
                key,
            )
            for i, (key, job) in enumerate(self._pending.items())
        ]
        self._seq += len(self._heap)
        heapq.heapify(self._heap)

    @classmethod
    def build(
        cls,
        items: list[StrategyItem],
        domains: list[str],
        *,
        weights: ScanWeights | None = None,
        epsilon: float = 0.1,
        seed: int | None = None,
    ) -> AdaptiveJobQueue:
        """Seed queue with full strategy × domain matrix."""
        q = cls(weights=weights, epsilon=epsilon, seed=seed)
        q._all_domains = list(domains)
        jobs = [AdaptiveJob.from_item(item, dom) for item in items for dom in domains]
        q.enqueue_many(jobs)
        q.metrics.set_half_mark(len(jobs))
        return q

    def pending_domains_for_strategy(self, label: str) -> list[str]:
        return [j.domain for j in self._pending.values() if j.item.label == label]

    def pop_batch(
        self,
        max_size: int = 1,
        *,
        protocol: str = "tls12",
        disable_ech: bool = False,
    ) -> list[AdaptiveJob]:
        """Pop up to *max_size* jobs with same strategy and compatible curl profile (AQ5)."""
        from blockchecks.engine.tcp_fanout import curl_profile, profiles_compatible

        first = self.pop()
        if not first:
            return []
        if max_size <= 1:
            return [first]
        prof = curl_profile(first.domain, protocol=protocol, disable_ech=disable_ech)
        # Mirror fanout_batches: googlevideo / special domains always solo
        if prof.special:
            return [first]
        batch = [first]
        for dom in self.pending_domains_for_strategy(first.item.label):
            if len(batch) >= max_size:
                break
            if dom == first.domain:
                continue
            p2 = curl_profile(dom, protocol=protocol, disable_ech=disable_ech)
            if not profiles_compatible(prof, p2):
                continue
            key = (first.item.label, dom)
            job = self._pending.pop(key, None)
            if job is not None:
                batch.append(job)
        if len(batch) > 1:
            self._rebuild_heap()
        return batch

    async def filter_resume(self, check, *, chunk_size: int = 512) -> int:
        """Drop pending jobs where *check(job)* is True. Returns skip count.

        The queue stays pure — I/O (e.g. SQLite completed-key lookup) lives in
        the caller's *check* callback. Checks run in chunks — unbounded gather
        over 100k+ jobs exhausts threads/FDs when *check* opens SQLite
        (EMFILE / can't start new thread).
        """
        import asyncio

        keys = list(self._pending.keys())
        if not keys:
            return 0
        jobs = [self._pending[k] for k in keys]
        step = max(1, int(chunk_size))
        flags: list[bool] = []
        for i in range(0, len(jobs), step):
            chunk = jobs[i : i + step]
            flags.extend(await asyncio.gather(*(check(j) for j in chunk)))
        skipped = 0
        for key, drop in zip(keys, flags, strict=True):
            if not drop:
                continue
            if key in self._pending:
                self._done.add(key)
                del self._pending[key]
                skipped += 1
        if skipped:
            self._rebuild_heap()
        return skipped
