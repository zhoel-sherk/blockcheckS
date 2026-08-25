"""Map nfqws2 lua-desync strings to ciadpi argv.
One ciadpi process per strategy. Untranslatable families return None.
nfqws2 repeats=N is N rawsends; byedpi offset:repeats:skip is split positions — not the same.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from blockchecks.engine.blob_aliases import resolve_blob_path

# Translation quality

#: FULL — 1:1 semantic match with byedpi argv.
#: PARTIAL — close but not bit-identical (repeats, droppable foolings, etc.).
#: NONE — untranslatable (returns None from translate()).
TRANSLATION_FULL = "full"
TRANSLATION_PARTIAL = "partial"
TRANSLATION_NONE = "none"


@dataclass
class Translation:
    """Result of translate() for one strategy line."""

    argv: list[str]
    quality: str = TRANSLATION_FULL
    notes: list[str] = field(default_factory=list)


# Unsupported nfqws2 features (byedpi has no equivalent)

_UNMAPPED_FOOLINGS = frozenset(
    {
        "badsum",
        "badsid",
        "badseq",
        "tcp_seq",
        "tcp_flags_unset",
        "tcp_flags_set",
        "ip_autottl",
        "ipfrag",
        "tcpseg",
        "padencap",
        "seqovl",
        "seqovl_pattern",
        "quic",
        "wssize",
        "circular",
        "dup",
        "tcp_ts",
    }
)

#: Unmapped when the option *name* starts with any of these prefixes (token boundary).
_UNMAPPED_FOOLING_PREFIXES = ("ip6_",)

#: Foolings with no ciadpi equivalent but droppable — family still translates
#: (the desync core works without them). Dropped with a PARTIAL note.
_DROPPABLE_FOOLINGS = frozenset({"tcp_ack", "tcp_ts_up"})

#: Families with a known ciadpi translation path.
_SUPPORTED_FAMILIES = frozenset(
    {
        "fake",
        "hostfakesplit",
        "fakedsplit",
        "fakeddisorder",
        "multisplit",
        "multidisorder",
        "tlsrec",
        "oob",
        "syndata",
    }
)

# nfqws2 pos → byedpi pos_t mapping

# byedpi pos_t: offset[:repeats:skip][+flag1[flag2]]
#   flags: +s SNI, +h Host, +n zero, +e end, +m mid, +r rand, +s start
_POS_MAP = {
    "midsld": "0+sm",
    "mid": "0+m",
    "start": "0",
    "end": "-1+e",
    "host": "0+h",
    "hostmid": "0+hm",
    "1": "1",
    "2": "2",
    "3": "3",
}
# Order matters for +flag matching in _match_pos.
_POS_FLAG_ORDER = (
    ("tls_", "+s"),
    ("sni_", "+s"),
    ("http_", "+h"),
    ("host_", "+h"),
)

_POS_RE = re.compile(r"pos=([^:\],]+)")
_MULTI_POS_RE = re.compile(r"pos=([^:]+)")
_BLOB_RE = re.compile(r"blob=([A-Za-z0-9_]+)")
_PATTERN_RE = re.compile(r"pattern=([A-Za-z0-9_]+)")
_REPEATS_RE = re.compile(r"repeats=(\d+)")
_TLS_REC_RE = re.compile(r"tlsrec:pos=([^:]+)")


def _pos_to_byedpi(pos_value: str) -> str:
    """Convert one nfqws2 position token to byedpi pos_t."""
    pos_value = pos_value.strip()
    if pos_value.isdigit():
        return pos_value
    if pos_value in _POS_MAP:
        return _POS_MAP[pos_value]
    # pos=host+N / pos=tls_1 etc. → relative SNI/Host offsets
    for prefix, flag in _POS_FLAG_ORDER:
        if pos_value.startswith(prefix):
            rest = pos_value[len(prefix) :]
            if rest.isdigit():
                return f"{rest}{flag}"
    return pos_value


def _first_match(text: str, rx: re.Pattern) -> str | None:
    m = rx.search(text)
    return m.group(1) if m else None


def _blob_argv(blob_name: str) -> list[str]:
    """Resolve a blob alias to a file and return -l argv (or [] if missing)."""
    path = resolve_blob_path(blob_name)
    if path and os.path.isfile(path):
        return ["-l", path]
    return []


def _desync_option_names(line: str) -> frozenset[str]:
    """Top-level nfqws2 desync option names (split on ``:`` / ``=``, not substrings)."""
    names: set[str] = set()
    for row in line.splitlines():
        row = row.strip()
        if not row:
            continue
        for segment in row.split(":"):
            seg = segment.strip().lower()
            if not seg:
                continue
            names.add(seg.split("=", 1)[0] if "=" in seg else seg)
    return frozenset(names)


def _has_unmapped_fooling(line: str) -> bool:
    names = _desync_option_names(line)
    return any(
        name in _UNMAPPED_FOOLINGS
        or any(name.startswith(prefix) for prefix in _UNMAPPED_FOOLING_PREFIXES)
        for name in names
    )


def _fooling_argv(line: str) -> tuple[list[str], list[str]]:
    """Map tcp_md5 fooling → byedpi flags; drop tcp_ack/tcp_ts_up.

    Returns (argv, notes). tcp_md5 maps to --md5sig. tcp_ack and tcp_ts_up
    have no ciadpi equivalent and are dropped (PARTIAL). tcp_ts* is
    untranslatable (checked before family translators).
    """
    names = _desync_option_names(line)
    argv: list[str] = []
    notes: list[str] = []
    if "tcp_md5" in names:
        argv.append("--md5sig")
    for bad in _DROPPABLE_FOOLINGS:
        if bad in names:
            notes.append(f"{bad} unsupported — dropped")
    return argv, notes


# Family translators


def _translate_fake(line: str) -> Translation:
    """fake:blob=X:repeats=N[:tcp_md5] → -f -1 -l @blob [--md5sig]."""
    argv = ["-f", "-1"]
    blob = _first_match(line, _BLOB_RE)
    if blob:
        argv.extend(_blob_argv(blob))
    fool, notes = _fooling_argv(line)
    argv.extend(fool)
    if _REPEATS_RE.search(line):
        notes.append("repeats=N has no ciadpi equivalent (single fake send)")
    return Translation(argv=argv, quality=TRANSLATION_PARTIAL, notes=notes)


def _translate_hostfakesplit(line: str) -> Translation:
    """hostfakesplit[:disorder_after]:nofake2[:tcp_md5] → --split 1+sm ..."""
    argv = ["--split", "1+sm"]
    if "disorder_after" in line or "disorder" in line:
        argv.extend(["--disorder", "1+sm"])
    fool, notes = _fooling_argv(line)
    argv.extend(fool)
    return Translation(argv=argv, quality=TRANSLATION_PARTIAL, notes=notes)


def _translate_fakedsplit(line: str) -> Translation:
    """fakedsplit:pos=N:pattern=X[:repeats] → --fake N --disorder N [-l @blob]."""
    pos = _pos_to_byedpi(_first_match(line, _POS_RE) or "1")
    argv = ["--fake", pos, "--disorder", pos]
    notes: list[str] = []
    blob = _first_match(line, _PATTERN_RE) or _first_match(line, _BLOB_RE)
    if blob:
        argv.extend(_blob_argv(blob))
    return Translation(argv=argv, quality=TRANSLATION_FULL, notes=notes)


def _translate_fakeddisorder(line: str) -> Translation:
    """fakeddisorder:pos=N:pattern=X → --disorder N --fake N [-l @blob]."""
    pos = _pos_to_byedpi(_first_match(line, _POS_RE) or "1")
    argv = ["--disorder", pos, "--fake", pos]
    blob = _first_match(line, _PATTERN_RE) or _first_match(line, _BLOB_RE)
    if blob:
        argv.extend(_blob_argv(blob))
    return Translation(argv=argv, quality=TRANSLATION_FULL)


def _translate_multisplit(line: str) -> Translation:
    """multisplit:pos=A,B[,...] → --split A --split B [--disorder first]."""
    pos_value = _first_match(line, _MULTI_POS_RE) or "1"
    positions = [p.strip() for p in pos_value.split(",") if p.strip()]
    argv: list[str] = []
    notes: list[str] = []
    for p in positions:
        argv.extend(["--split", _pos_to_byedpi(p)])
    if "disorder" in line and positions:
        argv.extend(["--disorder", _pos_to_byedpi(positions[0])])
    if "seqovl" in line:
        notes.append("seqovl unsupported — dropped")
    return Translation(argv=argv, quality=TRANSLATION_PARTIAL, notes=notes)


def _translate_tlsrec(line: str) -> Translation:
    """tlsrec:pos=N → -r N+s (split CH record inside SNI)."""
    pos = _pos_to_byedpi(_first_match(line, _POS_RE) or "1+s")
    return Translation(argv=["-r", pos], quality=TRANSLATION_FULL)


def _translate_oob(line: str) -> Translation:
    """oob:urp=b|s|m → -o 0 / -o 0+sm / -o 0+m (URG byte in SNI)."""
    urp = _first_match(line, re.compile(r"urp=([bsmc])")) or "b"
    pos = {"b": "0", "s": "0+sm", "m": "0+m", "c": "-1+e"}.get(urp, "0")
    return Translation(argv=["-o", pos], quality=TRANSLATION_FULL)


def _translate_syndata(line: str) -> Translation:
    """syndata → -f -1 [-Q rand|orig] (fake TLS ClientHello)."""
    argv = ["-f", "-1"]
    notes: list[str] = []
    if "tls_mod" in line:
        argv.extend(["-Q", "rand" if "rnd" in line else "orig"])
    if _REPEATS_RE.search(line):
        notes.append("repeats=N has no ciadpi equivalent")
    return Translation(argv=argv, quality=TRANSLATION_PARTIAL, notes=notes)


_FAMILY_TRANSLATORS = {
    "fake": _translate_fake,
    "hostfakesplit": _translate_hostfakesplit,
    "fakedsplit": _translate_fakedsplit,
    "fakeddisorder": _translate_fakeddisorder,
    "multisplit": _translate_multisplit,
    "multidisorder": _translate_multisplit,  # same family shape
    "tlsrec": _translate_tlsrec,
    "oob": _translate_oob,
    "syndata": _translate_syndata,
}


def _family_of(line: str) -> str | None:
    # Check more specific families first: "fakedsplit"/"fakeddisorder" also
    # start with "fake", "hostfakesplit" starts with "hostfake"+"split"→"fake".
    # Sorting by descending name length keeps longest-prefix matches first
    # regardless of set iteration order (which depends on PYTHONHASHSEED).
    for family in sorted(_SUPPORTED_FAMILIES, key=len, reverse=True):
        if line.startswith(family):
            return family
    return None


# Public API


def translate(strategy: str) -> Translation | None:
    """Translate one nfqws2 strategy line to ciadpi argv.

    Returns None (untranslatable → SKIP) when:
      * protocol is non-TCP (QUIC/UDP),
      * any unmapped fooling is present (badsum, seqovl, tcp_ack, ...),
      * no supported family prefix matches.
    """
    line = strategy.strip()
    if not line:
        return None

    if _has_unmapped_fooling(line):
        return None

    family = _family_of(line)
    if family is None:
        return None

    return _FAMILY_TRANSLATORS[family](line)


def translate_or_skip(strategy: str) -> list[str]:
    """Convenience wrapper: return argv list, or [] when unsupported."""
    t = translate(strategy)
    return t.argv if t is not None else []


def supported_families() -> frozenset[str]:
    """Families that have a ciadpi translation path."""
    return frozenset(_SUPPORTED_FAMILIES)


def is_supported(strategy: str) -> bool:
    """True when strategy can be translated (not SKIP)."""
    return translate(strategy) is not None


def can_translate(strategy: str) -> bool:
    """Alias for :func:`is_supported` (harvest / external validators)."""
    return is_supported(strategy)
