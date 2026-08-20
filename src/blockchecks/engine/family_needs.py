"""BC2-6 / B4: blockcheck2 need_* gating between standard strategy families."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from blockchecks.engine.generators.base import StrategyItem
from blockchecks.engine.generators.standard import TCP_FAMILIES

FAMILY_RANK = {name: idx for idx, name in enumerate(TCP_FAMILIES)}

LABEL_PREFIXES: dict[str, tuple[str, ...]] = {
    "fake": ("std_fake_", "fake_"),
    "hostfake": ("std_hostfake_", "hostfake_"),
    "multisplit": ("std_multisplit_", "multisplit_"),
    "syndata": ("std_syndata_",),
    "tcpseg": ("std_tcpseg_",),
    "oob": ("std_oob_",),
    "multi_fake": ("std_multi_fake_", "std_multi_", "fake_multi_"),
    "fake_multisplit": ("std_fms_", "fake_multisplit_"),
    "fake_multisplit_hostfake": ("std_fmsh_", "fake_multisplit_hostfake_"),
    "fake_multidisorder": ("std_fmd_", "fake_multidisorder_"),
    "multidisorder": ("std_mdis_", "multidisorder_"),
    "fakedsplit": ("std_fds_", "fakedsplit_"),
    "fakeddisorder": ("std_fdd_", "fakeddisorder_"),
    "fake_fakedsplit": ("std_ffds_", "fake_fakedsplit_"),
    "fake_hostfake": ("std_fake_hostfake_", "std_fh_", "fake_hostfake_"),
}


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
    for family in sorted(
        LABEL_PREFIXES.keys(),
        key=lambda name: max(len(p) for p in LABEL_PREFIXES[name]),
        reverse=True,
    ):
        if any(label.startswith(p) for p in LABEL_PREFIXES[family]):
            return family

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
    """Run TCP tests in family order with need_* gating (BC2-6).

    Returns (results, done, skipped, passed).
    """
    from blockchecks.engine.async_runner import TcpTestResult

    tracker = FamilyNeedTracker()
    sorted_items = sort_by_family(items)
    results: list[TcpTestResult] = []
    done = skipped = passed = 0
    idx = 0

    while idx < len(sorted_items):
        if stop_event and stop_event.is_set():
            break

        fam = classify_strategy_family(sorted_items[idx])
        family_items: list[StrategyItem] = []

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
                skipped += 1
                done += 1
                continue
            if tracker.skip_strategy(item, scan_level):
                skipped += 1
                done += 1
                continue
            family_items.append(item)

        if not family_items:
            tracker.finish_family(fam, False)
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
