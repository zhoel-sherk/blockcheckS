"""Phase 11 B11 — dynamic settle/curl timeouts from A9 bench-settle results."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

from blockchecks.engine.config import PROJECT_DIR
from blockchecks.engine.paths import SETTLE_PROFILE_FILE

PROFILE_VERSION = 1
DEFAULT_PROFILE_PATH = str(SETTLE_PROFILE_FILE)

# Auto-load guard: profiles whose defaults demand a curl budget below this are
# rejected on auto-load (they usually went stale on a throttled network and
# would turn every TCP probe into a 500ms FAIL). Explicit --settle-profile
# still forces them through.
AUTO_LOAD_MIN_CURL = 2.0


@dataclass
class TimingOverride:
    settle_max: float
    curl_timeout: float


@dataclass
class SettleProfile:
    """Per-strategy settle/curl overrides from bench-settle (B11)."""

    domain: str = ""
    defaults: TimingOverride | None = None
    strategies: dict[str, TimingOverride] = field(default_factory=dict)
    source_path: str = ""

    def lookup(self, strategy: str) -> TimingOverride | None:
        key = strategy.strip()
        if key in self.strategies:
            return self.strategies[key]
        # Multi-line strategy configs: match first line
        first = key.split("\n", 1)[0].strip()
        if first in self.strategies:
            return self.strategies[first]
        return self.defaults

    def settle_max_for(self, strategy: str) -> float | None:
        o = self.lookup(strategy)
        return o.settle_max if o else None

    def curl_timeout_for(self, strategy: str) -> float | None:
        o = self.lookup(strategy)
        return o.curl_timeout if o else None


def build_profile_from_rows(
    rows: list[dict],
    *,
    domain: str,
) -> SettleProfile:
    """Pick min settle + min passing curl per strategy from bench grid."""
    by_strategy: dict[str, list[dict]] = {}
    for row in rows:
        if not row.get("ok"):
            continue
        strat = row.get("strategy_full") or row.get("strategy", "")
        if not strat:
            continue
        by_strategy.setdefault(strat, []).append(row)

    strategies: dict[str, TimingOverride] = {}
    all_settles: list[float] = []
    all_curls: list[float] = []

    for strat, passes in by_strategy.items():
        best = min(passes, key=lambda r: (r["settle_max"], r["curl_t"]))
        strategies[strat] = TimingOverride(
            settle_max=float(best["settle_max"]),
            curl_timeout=float(best["curl_t"]),
        )
        all_settles.append(best["settle_max"])
        all_curls.append(best["curl_t"])

    defaults = None
    if all_settles:
        defaults = TimingOverride(
            settle_max=min(all_settles),
            curl_timeout=min(all_curls) if all_curls else 1.5,
        )

    return SettleProfile(domain=domain, defaults=defaults, strategies=strategies)


def save_profile(profile: SettleProfile, path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    payload = {
        "version": PROFILE_VERSION,
        "domain": profile.domain,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "defaults": (
            {
                "settle_max": profile.defaults.settle_max,
                "curl_timeout": profile.defaults.curl_timeout,
            }
            if profile.defaults
            else None
        ),
        "strategies": {
            k: {"settle_max": v.settle_max, "curl_timeout": v.curl_timeout}
            for k, v in profile.strategies.items()
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")
    return path


def load_profile(path: str | None = None) -> SettleProfile | None:
    """Load settle profile JSON; None if missing or invalid."""
    p = path or os.environ.get("BLOCKCHECKS_SETTLE_PROFILE", "").strip()
    if not p:
        p = DEFAULT_PROFILE_PATH
    if not os.path.isabs(p):
        p = os.path.join(PROJECT_DIR, p) if not os.path.exists(p) else p
    if not os.path.exists(p):
        return None
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    defaults = None
    if data.get("defaults"):
        defaults = TimingOverride(
            settle_max=float(data["defaults"]["settle_max"]),
            curl_timeout=float(data["defaults"]["curl_timeout"]),
        )
    strategies = {
        k: TimingOverride(
            settle_max=float(v["settle_max"]),
            curl_timeout=float(v["curl_timeout"]),
        )
        for k, v in (data.get("strategies") or {}).items()
    }
    return SettleProfile(
        domain=data.get("domain", ""),
        defaults=defaults,
        strategies=strategies,
        source_path=p,
    )


def auto_load_profile() -> SettleProfile | None:
    """Load profile from env or default logs path (safe auto-load).

    A profile whose defaults demand an aggressive curl budget (<
    ``AUTO_LOAD_MIN_CURL``) is ignored on auto-load — it is most likely stale
    from a previously faster/throttled network and would fail every TCP probe
    (e.g. curl timeout 0.5s on Fryazino). Use ``--settle-profile`` to force it.
    """
    env = os.environ.get("BLOCKCHECKS_SETTLE_PROFILE", "").strip()
    if env.lower() in ("0", "off", "false", "no"):
        return None
    profile = load_profile(env or None)
    if profile is None:
        return None
    d = profile.defaults
    if d is not None and d.curl_timeout is not None and d.curl_timeout < AUTO_LOAD_MIN_CURL:
        print(
            "  [settle] auto profile ignored: curl_timeout "
            f"{d.curl_timeout}s < {AUTO_LOAD_MIN_CURL}s (likely stale; "
            "use --settle-profile to force)"
        )
        return None
    return profile
