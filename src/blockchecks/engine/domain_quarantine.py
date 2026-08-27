"""Mid-run domain quarantine: stop probing domains that never PASS.

A domain is quarantined once it accumulated ``min_attempts`` failed probes
(0 PASS) within the current campaign — plus, on ``--resume`` only, whatever
the campaign DB already holds. Without ``--resume``, historical FAIL rows
must not pre-exclude domains (append-only re-runs need a fresh clock).
Infrastructure FAILs (shm EPERM, batch-loop abort, ns pool) do not count.
Quarantined domains stop being scheduled (AQ
``pop(exclude_domains=...)``, fan-out/sequential domain filters), are logged
loudly, persisted to the campaign DB (``quarantined`` table) so MCP
``get_series_status`` can surface them, and — with
``--quarantine-auto-denylist`` — appended to the runtime denylist.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

#: Fallback when no explicit threshold is provided (--quarantine-min).
DEFAULT_MIN_ATTEMPTS = 300

#: Statuses that prove a domain is reachable (same as store latest-row working).
_WORKING_PROBE_STATUSES = frozenset({"PASS", "THROTTLED"})


@dataclass(slots=True)
class _DomainStats:
    attempts: int = 0
    passed: int = 0


@dataclass
class QuarantineConfig:
    enabled: bool = True
    min_attempts: int = DEFAULT_MIN_ATTEMPTS
    auto_denylist: bool = False


@dataclass
class DomainQuarantine:
    """Per-campaign quarantine tracker (event-loop thread only)."""

    config: QuarantineConfig = field(default_factory=QuarantineConfig)
    stats: dict[str, _DomainStats] = field(default_factory=dict)
    quarantined: dict[str, dict] = field(default_factory=dict)

    def seed_from_rows(self, rows: list[tuple[str, int, int]]) -> list[str]:
        """Pre-quarantine from a bulk (domain, total, passed) DB query.

        Used on ``--resume`` so domains already known-dead from previous
        sessions of the same campaign DB are skipped immediately instead of
        re-burning ``min_attempts`` probes.
        """
        newly: list[str] = []
        if not self.config.enabled:
            return newly
        for domain, total, passed in rows:
            st = self.stats.setdefault(domain, _DomainStats(total, passed))
            if (
                domain not in self.quarantined
                and st.attempts >= self.config.min_attempts
                and st.passed == 0
            ):
                self._mark(domain, st)
                newly.append(domain)
        return newly

    def record(
        self,
        domain: str,
        passed: bool,
        *,
        status: str | None = None,
        fail_phase: str = "",
        error: str = "",
    ) -> str | None:
        """Account one probe result; return domain name if just quarantined.

        When ``status`` is provided, PASS and THROTTLED count as success (working
        probes). Otherwise ``passed`` is used as-is for backward compatibility.
        Infra/synthetic FAILs do not increment ``attempts``.
        """
        if not self.config.enabled or domain in self.quarantined:
            return None
        counts_pass = (
            status in _WORKING_PROBE_STATUSES if status is not None else passed
        )
        if counts_pass:
            st = self.stats.setdefault(domain, _DomainStats())
            st.attempts += 1
            st.passed += 1
            return None
        from blockchecks.engine.fail_phase import is_infra_fail_phase

        if is_infra_fail_phase(fail_phase, error=error):
            log.debug(
                "quarantine skip infra FAIL %s fail_phase=%r error=%r",
                domain,
                fail_phase,
                (error or "")[:160],
            )
            return None
        st = self.stats.setdefault(domain, _DomainStats())
        st.attempts += 1
        if st.attempts < self.config.min_attempts or st.passed:
            return None
        self._mark(domain, st)
        return domain

    def exclude_domains(self) -> set[str]:
        return set(self.quarantined)

    def _mark(self, domain: str, st: _DomainStats) -> None:
        info = {
            "domain": domain,
            "attempts": st.attempts,
            "passed": st.passed,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "reason": f"0 PASS in {st.attempts} attempts",
        }
        self.quarantined[domain] = info
        log.warning(
            "%s",
            f"  [quarantine] {domain}: {info['reason']} this campaign — "
            f"skipping for the rest of the run"
            + (" (auto-denylist)" if self.config.auto_denylist else ""),
        )


def append_denylist(entries: list[dict], denylist_path: str | None = None) -> list[str]:
    """Append quarantined domains to denylist.txt; returns written lines.

    Only called with ``--quarantine-auto-denylist``. Existing entries are not
    duplicated (exact-FQDN match on the first whitespace-separated token).
    """
    from blockchecks.engine.domain_loader import DENYLIST_FILE

    path = denylist_path or str(DENYLIST_FILE)
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        existing: set[str] = set()
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    token = line.split("#", 1)[0].strip().lower()
                    if token:
                        existing.add(token)
        except FileNotFoundError:
            pass
        written: list[str] = []
        with open(path, "a", encoding="utf-8") as fh:
            for e in entries:
                dom = (e.get("domain") or "").strip().lower()
                if not dom or dom in existing:
                    continue
                line = (
                    f"{dom}  # auto-quarantine {e.get('ts', '')} "
                    f"({e.get('reason', '')})\n"
                )
                fh.write(line)
                written.append(dom)
                existing.add(dom)
        if written:
            log.warning(
                "%s",
                f"  [quarantine] appended {len(written)} domains to {path}: "
                f"{', '.join(written)}",
            )
        return written
    except OSError as exc:
        log.warning("%s", f"  [quarantine] denylist append failed ({exc})")
        return []


def quarantine_from_args(args) -> QuarantineConfig | None:
    """Build a QuarantineConfig from campaign CLI args (None = disabled)."""
    if getattr(args, "no_quarantine", False):
        return None
    return QuarantineConfig(
        enabled=True,
        min_attempts=(
            DEFAULT_MIN_ATTEMPTS
            if (raw := getattr(args, "quarantine_min", None)) is None
            else int(raw)
        ),
        auto_denylist=bool(getattr(args, "quarantine_auto_denylist", False)),
    )
