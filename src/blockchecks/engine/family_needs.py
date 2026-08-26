"""Map triage flags to which standard strategy families to run."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from blockchecks.engine.family_spec import LABEL_PREFIXES, TCP_FAMILIES
from blockchecks.engine.generators.base import StrategyItem

FAMILY_RANK = {name: idx for idx, name in enumerate(TCP_FAMILIES)}


def map_triage_to_generators(profile) -> list[str]:
    """Recommend standard strategy families from a TriageProfile.

    Deterministic mapping used by the MCP ``triage`` action and generator
    pruning. Names match ``StandardGenerator`` expanders (not CLI aliases).
    """
    from blockchecks.engine.family_registry import families_for_profile

    return families_for_profile(profile)


def classify_strategy_family(item: StrategyItem) -> str:
    """Map a strategy item to a standard family name (or 'other')."""
    label = item.label.lower()
    hits = sorted(
        (
            (prefix, family)
            for family, prefixes in LABEL_PREFIXES.items()
            for prefix in prefixes
            if label.startswith(prefix)
        ),
        key=lambda pair: len(pair[0]),
        reverse=True,
    )
    if hits:
        return hits[0][1]

    strat = item.strategy.lower()
    if "hostfakesplit" in strat:
        return "hostfake"
    if "multisplit" in strat or "multidisorder" in strat:
        return "multisplit"
    if "fakedsplit" in strat or "fakeddisorder" in strat:
        return "faked"

    if label.startswith("std_"):
        parts = label.split("_")
        if len(parts) >= 2 and parts[1] in TCP_FAMILIES:
            return parts[1]
    return "other"


def sort_by_family(items: list[StrategyItem]) -> list[StrategyItem]:
    """Order strategies by blockcheck2 standard family sequence."""
    return sorted(
        items,
        key=lambda item: (FAMILY_RANK.get(classify_strategy_family(item), 999), item.label),
    )


@dataclass
class FamilyNeedTracker:
    """Mirror blockcheck2 need_* flags (0 = family passed, skip dependents)."""

    need_fake: int = 1
    need_hostfakesplit: int = 1
    need_multisplit: int = 1
    need_multidisorder: int = 1
    need_fakedsplit: int = 1
    need_fakeddisorder: int = 1

    def finish_family(self, family: str, had_pass: bool) -> None:
        val = 0 if had_pass else 1
        if family == "fake":
            self.need_fake = val
        elif family == "hostfake":
            self.need_hostfakesplit = val
        elif family == "multisplit":
            self.need_multisplit = val
            self.need_multidisorder = val
        elif family in ("faked", "fakedsplit", "fakeddisorder"):
            self.need_fakedsplit = val
            self.need_fakeddisorder = val

    def skip_family(self, family: str, scan_level: str) -> bool:
        if scan_level == "full":
            return False
        return family == "fake_hostfake" and self.need_hostfakesplit == 0

    def skip_strategy(self, item: StrategyItem, scan_level: str) -> bool:
        if scan_level == "full":
            return False
        strat = item.strategy
        return (
            (self.need_multisplit == 0 and ("multisplit" in strat or "multidisorder" in strat))
            or (self.need_fakedsplit == 0 and "fakedsplit" in strat)
            or (self.need_fakeddisorder == 0 and "fakeddisorder" in strat)
        )


ProgressCb = Callable[[int, int, int], None]  # done, skipped, passed
ResumeCb = Callable[[str, str], Awaitable[bool]]


async def run_tcp_with_family_gates(
    runner,
    items: list[StrategyItem],
    domain: str,
    *,
    scan_level: str,
    timeout: float,
    stop_event: asyncio.Event | None = None,
    on_progress: ProgressCb | None = None,
    resume_check: ResumeCb | None = None,
) -> tuple[list, int, int, int]:
    """Run TCP tests in family order with need_* gating.

    Returns (results, done, skipped, passed).
    """
    from blockchecks.engine.async_runner import TcpTestResult

    tracker = FamilyNeedTracker()
    sorted_items = sort_by_family(items)
    results: list[TcpTestResult] = []
    done = skipped = passed = 0
    idx = 0

    working_tcp: set[str] | None = None
    if resume_check is not None:
        db = getattr(runner, "db", None)
        get_working = getattr(db, "get_working_tcp", None) if db is not None else None
        if asyncio.iscoroutinefunction(get_working):
            working_tcp = set(await get_working(domain))

    while idx < len(sorted_items):
        if stop_event and stop_event.is_set():
            break

        fam = classify_strategy_family(sorted_items[idx])
        family_items: list[StrategyItem] = []
        family_skipped_labels: list[str] = []

        if tracker.skip_family(fam, scan_level):
            while idx < len(sorted_items) and classify_strategy_family(sorted_items[idx]) == fam:
                skipped += 1
                done += 1
                idx += 1
            tracker.finish_family(fam, False)
            if on_progress:
                on_progress(done, skipped, passed)
            continue

        while idx < len(sorted_items) and classify_strategy_family(sorted_items[idx]) == fam:
            item = sorted_items[idx]
            idx += 1
            if resume_check and await resume_check(item.label, domain):
                family_skipped_labels.append(item.label)
                skipped += 1
                done += 1
                continue
            if tracker.skip_strategy(item, scan_level):
                skipped += 1
                done += 1
                continue
            family_items.append(item)

        if not family_items:
            had_pass = bool(
                working_tcp and any(label in working_tcp for label in family_skipped_labels)
            )
            tracker.finish_family(fam, had_pass)
            if on_progress:
                on_progress(done, skipped, passed)
            continue

        had_pass = False
        for item in family_items:
            if stop_event and stop_event.is_set():
                break
            result = await runner.test_tcp(item, domain, timeout=timeout)
            results.append(result)
            done += 1
            if result.success:
                passed += 1
                had_pass = True
                if scan_level == "single":
                    tracker.finish_family(fam, True)
                    if on_progress:
                        on_progress(done, skipped, passed)
                    return results, done, skipped, passed
            if on_progress and done % 50 == 0:
                on_progress(done, skipped, passed)

        tracker.finish_family(fam, had_pass)
        if on_progress:
            on_progress(done, skipped, passed)

    return results, done, skipped, passed
