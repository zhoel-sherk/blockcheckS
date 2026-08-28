"""Offline checks on nfqws2 strategy strings. No I/O. Does not raise on bad input."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["error", "warning", "info"]

# Desync technique family names embedded in strategy strings.
_SPLIT_FAMILIES = (
    "split2",
    "multisplit",
    "nmultisplit",
    "fakedsplit",
    "nfakedsplit",
    "fakeddisorder",
    "multidisorder",
    "hostfakesplit",
    "nhostfakesplit",
    "fake_fakedsplit",
    "fake_multisplit",
    "fake_multisplit_hostfake",
    "fake_fakeddisorder",
    "fake_multidisorder",
)
# Families whose leading token is an explicit fake source marker
# (require blob=/pattern=). ``hostfakesplit`` fakes via host SNI — no blob.
_FAKE_MARKERS = ("fake", "dupfake", "multi_fake", "multifake", "fake_default")
_BLOB_RE = re.compile(r"(?:blob|pattern|seqovl_pattern)=([A-Za-z0-9_]+)")
_POS_RE = re.compile(r"pos=([A-Za-z0-9_,:]+)")
# Numeric params as whole tokens (not inside e.g. ip_autottl); ttl/ip_ttl only.
_NUM_PARAM = re.compile(r"(?:^|:)(tcp_ts|tcp_ack|tcp_seq|ip_ttl|ttl)=([^:\s]+)")


@dataclass
class ValidationIssue:
    """A single static validation finding for a strategy string."""

    code: str
    message: str
    severity: Severity = "warning"


@dataclass
class StrategyValidationResult:
    """Full validation outcome for one strategy string."""

    strategy: str
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not any(i.severity == "error" for i in self.issues)

    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == "error"]


def _extract_blobs(strategy: str) -> list[str]:
    return list(dict.fromkeys(m.group(1) for m in _BLOB_RE.finditer(strategy)))


def _leading_family(strategy: str) -> str | None:
    """First token up to ':' (e.g. ``hostfakesplit``, ``fake``, ``multisplit``)."""
    token = strategy.strip().split(":", 1)[0].strip()
    return token.lower() or None


def _is_fake_family(strategy: str) -> bool:
    fam = _leading_family(strategy)
    return fam in _FAKE_MARKERS


def _is_split_family(strategy: str) -> bool:
    fam = _leading_family(strategy)
    if fam in _SPLIT_FAMILIES:
        return True
    # composite families (e.g. fake+multisplit) also carry split semantics
    low = strategy.lower()
    return any(name in low and name != "hostfakesplit" for name in _SPLIT_FAMILIES)


def _is_well_formed(strategy: str) -> bool:
    """Reject broken UTF-8 / unbalanced quotes / unterminated escapes."""
    try:
        strategy.encode("utf-8").decode("utf-8")
    except UnicodeError:
        return False
    # strategy strings are single-line; embedded newlines are a config-injection risk
    if "\n" in strategy or "\r" in strategy:
        return False
    return strategy.count('"') % 2 == 0


def validate_strategy(
    strategy: str,
    *,
    blobs_dir: str | None = None,
) -> StrategyValidationResult:
    """Validate a single nfqws2 strategy string (never raises).

    Literal ``\\n`` between strategy cores is a supported multi-desync
    separator (e.g. ``fake:blob=stun…\\nfake:blob=max_ru…``); each core is
    validated independently and issues are aggregated.

    ``blobs_dir`` is optional; when omitted the canonical search bases
    (BLOCKCHECKS_BLOBS → repo blobs/ → /opt/zapret2/blobs) are consulted.
    """
    result = StrategyValidationResult(strategy=strategy)
    raw = strategy or ""

    if not raw.strip():
        result.issues.append(ValidationIssue("empty_strategy", "Strategy string is empty", "error"))
        return result

    if not _is_well_formed(raw):
        result.issues.append(
            ValidationIssue(
                "malformed",
                "Strategy contains broken encoding, unbalanced quotes, or a raw newline",
                "error",
            )
        )
        return result

    # Multi-core strategies use a literal backslash-n separator.
    parts = raw.split("\\n") if "\\n" in raw else [raw]
    for part in parts:
        seg = part.strip()
        if not seg:
            continue
        result.issues.extend(_validate_single(seg, blobs_dir=blobs_dir).issues)

    return result


def _warn_digit_blob_ids(result: StrategyValidationResult, blobs: list[str]) -> None:
    """nfqws2 rejects identifiers that start with a digit (4pda → b4pda)."""
    from blockchecks.engine.blob_aliases import safe_blob_name

    for name in blobs:
        if name[:1].isdigit() and not re.fullmatch(r"0x[0-9a-fA-F]+", name):
            result.issues.append(
                ValidationIssue(
                    "digit_blob_id",
                    (
                        f"blob/pattern '{name}' starts with a digit "
                        f"(nfqws2 fatal identifier); runtime/export uses "
                        f"'{safe_blob_name(name)}'"
                    ),
                    "warning",
                )
            )


def _validate_single(
    raw: str,
    *,
    blobs_dir: str | None,
) -> StrategyValidationResult:
    """Validate one strategy core (no \\n separator, no empty check)."""
    result = StrategyValidationResult(strategy=raw)
    tokens = raw.strip().split()
    is_fake = _is_fake_family(raw)
    is_split = _is_split_family(raw)
    blobs = _extract_blobs(raw)
    _warn_digit_blob_ids(result, blobs)

    # blob requirements
    if is_fake and not blobs:
        result.issues.append(
            ValidationIssue(
                "fake_without_blob",
                "Fake desync specified without blob=/pattern= source",
                "error",
            )
        )

    # blob existence (skips builtin aliases / 0x00000000 / hex pattern literals)
    for name in blobs:
        from blockchecks.engine.blob_aliases import (
            _BUILTIN_BLOBS,
            BLOB_ALIAS_MAP,
            resolve_blob_path,
        )

        if name == "0x00000000" or name in _BUILTIN_BLOBS:
            continue
        if re.fullmatch(r"0x[0-9a-fA-F]+", name):
            continue  # hex pattern literal, not a named blob file
        if name in BLOB_ALIAS_MAP:
            continue  # canonical alias; existence is resolved at runtime
        if resolve_blob_path(name, blobs_dir):
            continue
        result.issues.append(
            ValidationIssue(
                "unknown_blob",
                f"blob/pattern '{name}' not found in blobs dirs and not a known alias",
                "error",
            )
        )

    # split families need pos=
    if is_split and not _POS_RE.search(raw):
        result.issues.append(
            ValidationIssue(
                "split_without_pos",
                "Split-family desync selected without specifying pos= offset",
                "warning",
            )
        )

    # numeric parameter ranges
    for param, value in _NUM_PARAM.findall(raw):
        if param in ("ip_ttl", "ttl"):
            try:
                v = int(value)
            except ValueError:
                result.issues.append(
                    ValidationIssue(
                        "non_numeric_param",
                        f"{param} is not a valid integer: {value!r}",
                        "error",
                    )
                )
                continue
            if not 0 <= v <= 255:
                result.issues.append(
                    ValidationIssue(
                        f"invalid_{param}",
                        f"{param}={v} out of range 0..255",
                        "error",
                    )
                )
        elif param in ("tcp_ts", "tcp_ack", "tcp_seq"):
            try:
                v = int(value)
            except ValueError:
                result.issues.append(
                    ValidationIssue(
                        "non_numeric_param",
                        f"{param} is not a valid integer: {value!r}",
                        "error",
                    )
                )
                continue
            if not -(1 << 31) <= v <= (1 << 31) - 1:
                result.issues.append(
                    ValidationIssue(
                        f"invalid_{param}",
                        f"{param}={v} outside int32 range",
                        "error",
                    )
                )

    # repeats (accept negative to flag error)
    for m in re.finditer(r"repeats=(-?\d+)", raw):
        r = int(m.group(1))
        if not 1 <= r <= 20:
            result.issues.append(
                ValidationIssue(
                    "repeats_range",
                    f"repeats={r} outside 1..20",
                    "error" if r < 1 else "warning",
                )
            )

    # informational: unescaped '<' (conf-file hazard)
    if "<" in raw and not any(t.startswith('"') for t in tokens):
        result.issues.append(
            ValidationIssue(
                "unescaped_lt",
                "Unescaped '<' in strategy; escape as \\< for @conf files",
                "info",
            )
        )

    # custom Lua manifest params (excluded → error, undocumented → warning)
    from blockchecks.engine.conf_builder import validate_custom_lua_params

    for msg in validate_custom_lua_params(raw):
        if "is excluded" in msg:
            result.issues.append(ValidationIssue("custom_lua_excluded", msg, "error"))
        else:
            result.issues.append(ValidationIssue("custom_lua_undocumented", msg, "warning"))

    return result


def validate_strategies(
    strategies: list[str],
    *,
    blobs_dir: str | None = None,
) -> list[StrategyValidationResult]:
    """Validate a batch of strategy strings (no shared mutable state)."""
    return [validate_strategy(s, blobs_dir=blobs_dir) for s in strategies]
