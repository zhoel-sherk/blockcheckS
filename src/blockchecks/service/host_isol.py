"""Host-mode isolation (fwmark): nft table ``inet blockchecks_host``.

Canon: docs/hostmode.md §5–§8, §18. Scheme B — the queue sees ONLY the probe
socket (``meta skuid``), never the whole :443 of other apps, never dst-IP
(scheme A is rejected).

Datapath (TCP v1):

    curl worker (uid bcprobe) ── tcp/443 ──▶ nft inet blockchecks_host output
        meta skuid bcprobe && tcp dport 443
        && mark & DESYNC_MARK == 0            (rawsend fakes never re-queued)
        && ct original packets 1-MAX_PKT_OUT  (first packets of the flow only,
                                               upstream manual pattern)
        → queue num HOST_QNUM bypass

    predefrag (output, prio -401): mark & DESYNC_MARK != 0 → notrack
    (generated fakes must not be NAT/conntrack-validated; upstream manual).

Inbound RST/SYN-ACK capture is NOT in v1 (canon §14: injected RSTs are
conntrack-INVALID, ct mark restore misses them; v1 verdict = HTTP, not rst_in).

Invariants (§18): no silent fallback (missing nft/uid/busy qnum → error);
teardown = delete OUR table only; never ``iptables -F``/``flush ruleset``.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

from blockchecks.engine.config import (
    DESYNC_MARK,
    HOST_PROBE_USER,
    HOST_QNUM_TCP,
    PROBE_MARK,
)

log = logging.getLogger(__name__)

NFT_TABLE = "blockchecks_host"
DEFAULT_DPORT = 443
DEFAULT_MAX_PKT_OUT = 15


def nft_available() -> bool:
    return shutil.which("nft") is not None


def _nft(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["sudo", "-n", "nft", *args], capture_output=True, text=True, timeout=15, check=check
    )


def table_exists() -> bool:
    return _nft("list", "table", "inet", NFT_TABLE).returncode == 0


def _list_ruleset() -> str:
    r = _nft("list", "ruleset")
    return r.stdout if r.returncode == 0 else ""


def qnum_busy(qnum: int) -> str | None:
    """Return the owner description if qnum is already queued anywhere.

    AUDIT hostmode §6: a busy queue is a hard refusal (no silent rotation to
    the next number). Scans the whole ruleset — our own table AND foreign ones
    (a production nfqws2 on 200 must be visible before we take 220). Two
    renderings exist in ``nft list ruleset`` output:
    - iptables-nft/legacy-compat rules: ``queue num 200 bypass``
    - nft-native queue statements: ``queue flags bypass to 220``
    Rules belonging to OUR table never count as busy (attach/teardown own it).
    """
    ruleset = _list_ruleset()
    if not ruleset:
        return None
    needle = f"queue num {qnum}"
    to_re = re.compile(rf"\bqueue\b[^;\n]*\bto\s+{qnum}\b")
    current_table = ""
    for line in ruleset.splitlines():
        stripped = line.strip()
        if stripped.startswith("table "):
            tokens = stripped.split()
            # "table <family> <name> {" (nft list); single-line compact form
            # "table <family> <name> { rules }" is handled too (tests, §16).
            current_table = tokens[2] if len(tokens) > 2 else (tokens[1] if len(tokens) > 1 else "")
        if needle in line or to_re.search(line):
            if current_table == NFT_TABLE:
                continue  # our own table is managed by attach/teardown
            return f"{current_table}: {stripped[:110]}"
    return None


def build_queue_rules(
    *,
    skuid: str,
    qnum: int = HOST_QNUM_TCP,
    desync_mark: int = DESYNC_MARK,
    probe_mark: int = PROBE_MARK,
    dport: int = DEFAULT_DPORT,
    max_pkt_out: int = DEFAULT_MAX_PKT_OUT,
) -> list[str]:
    """OUTPUT queue rules (pure builder — unit-tested).

    ``probe_mark`` adds ``meta mark set`` on the matched skb — only useful
    together with nfqws2 ``--filter-mark`` (v1.0.5). On the current binary
    probe_mark stays 0 → mark is never set, pure skuid matching.
    """
    mark_ok = f"meta mark and 0x{desync_mark:x} == 0"
    pkt_window = f"ct original packets 1-{max_pkt_out}"
    mark_set = f"meta mark set 0x{probe_mark:x} " if probe_mark else ""
    return [
        f"meta skuid {skuid} tcp dport {dport} {mark_ok} {pkt_window} "
        f"{mark_set}queue num {qnum} bypass",
    ]


def build_notrack_rule(desync_mark: int = DESYNC_MARK) -> str:
    return f"mark & 0x{desync_mark:x} != 0x00000000 notrack"


def attach_host_queue(
    *,
    skuid: str = HOST_PROBE_USER,
    qnum: int = HOST_QNUM_TCP,
    desync_mark: int = DESYNC_MARK,
    probe_mark: int = PROBE_MARK,
    dport: int = DEFAULT_DPORT,
    max_pkt_out: int = DEFAULT_MAX_PKT_OUT,
) -> None:
    """Create/recreate ``inet blockchecks_host`` with the scheme-B queue rule.

    Hard refusals (no silent fallback, §18.1): nft missing, probe uid missing,
    qnum owned by a foreign table. Recreating an existing OUR table is fine —
    the previous session must have torn it down; leftovers from a kill -9 are
    cleared here (delete + create is the documented teardown contract §7).
    """
    import pwd

    if not nft_available():
        raise RuntimeError("probe-isol=host requires nft; not found in PATH")
    try:
        pwd.getpwnam(skuid)
    except KeyError:
        raise RuntimeError(
            f"probe-isol=host requires probe uid {skuid!r} for the nft skuid match; "
            "refusing to queue the whole :443 (scheme A rejected)"
        ) from None
    owner = qnum_busy(qnum)
    if owner:
        raise RuntimeError(
            f"host qnum {qnum} is already queued by: {owner!r}. "
            "Pick another --host-qnum explicitly (busy queue is a refusal, not a fallback)"
        )

    if table_exists():
        log.warning("host nft table %s left from a previous session — recreating", NFT_TABLE)
        _nft("delete", "table", "inet", NFT_TABLE)

    _nft("create", "table", "inet", NFT_TABLE, check=True)
    _nft(
        "add",
        "chain",
        "inet",
        NFT_TABLE,
        "output",
        "{ type filter hook output priority mangle; }",
        check=True,
    )
    _nft(
        "add",
        "chain",
        "inet",
        NFT_TABLE,
        "predefrag",
        "{ type filter hook output priority -401; }",
        check=True,
    )
    notrack = build_notrack_rule(desync_mark)
    _nft("add", "rule", "inet", NFT_TABLE, "predefrag", notrack, check=True)
    for rule in build_queue_rules(
        skuid=skuid,
        qnum=qnum,
        desync_mark=desync_mark,
        probe_mark=probe_mark,
        dport=dport,
        max_pkt_out=max_pkt_out,
    ):
        _nft("add", "rule", "inet", NFT_TABLE, "output", rule, check=True)
    log.info(
        "%s",
        f"host queue attached: table={NFT_TABLE} qnum={qnum} skuid={skuid} "
        f"probe_mark={f'0x{probe_mark:x}' if probe_mark else 'off'}",
    )


def hostify_conf_text(
    conf_text: str,
    *,
    qnum: int,
    desync_mark: int,
    probe_mark: int = PROBE_MARK,
) -> str:
    """Rewrite an operator .conf for the host slot (AUDIT hostmode §6).

    Overrides ``--qnum`` with the host queue, injects the mandatory
    ``--fwmark`` anti-loop line and, when ``probe_mark`` is set, the
    ``--filter-mark`` second lock (binary >= 1.0.5; must mirror the nft
    ``meta mark set`` rule — they only work as a pair). Foreign
    ``--filter-mark``/``--fwmark`` lines are replaced, never accumulated.
    Pure function — used by composite overlay and TestRunner._hostify_conf.
    """
    filter_mark_line = (
        f"--filter-mark=0x{probe_mark:x}/0x{probe_mark:x}" if probe_mark else ""
    )
    lines: list[str] = []
    inserted = False
    for raw in conf_text.splitlines():
        s = raw.strip()
        if s.startswith("--qnum="):
            lines.append(f"--qnum={qnum}")
            lines.append(f"--fwmark={desync_mark:#x}")
            if filter_mark_line:
                lines.append(filter_mark_line)
            inserted = True
            continue
        if s.startswith("--fwmark=") or s.startswith("--filter-mark="):
            continue
        lines.append(raw)
    if not inserted:
        lines.insert(0, f"--qnum={qnum}")
        lines.insert(1, f"--fwmark={desync_mark:#x}")
        if filter_mark_line:
            lines.insert(2, filter_mark_line)
    return "\n".join(lines) + "\n"


def queue_bound(qnum: int) -> bool:
    """True when a listener owns this NFQUEUE (live-bind probe).

    ``/proc/net/netfilter/nfnetlink_queue`` row: portid (2nd column) != 0/−1
    means a userspace consumer is attached. The stdout-marker alternative is
    unreliable — nfqws2 writes to a redirected file fully buffered, so the
    marker only flushes on exit (AUDIT §16 acceptance lesson).
    """
    q = Path("/proc/net/netfilter/nfnetlink_queue")
    if not q.exists():
        return False
    try:
        for line in q.read_text().splitlines():
            parts = line.split()
            if parts and parts[0] == str(qnum) and len(parts) > 1 and parts[1] not in ("0", "-1"):
                return True
    except OSError:
        return False
    return False


def teardown_host_queue(*, expect_absent: bool = False) -> bool:
    """Delete OUR table (single teardown contract, §7/§18.2). Never flush.

    Returns True when the table is gone afterwards. A missing table is
    expected after a normal shutdown (debug, not warning — every command
    teardown would otherwise spam, AUDIT A7 lesson).
    """
    r = _nft("delete", "table", "inet", NFT_TABLE)
    if r.returncode == 0:
        log.info("host nft table %s deleted", NFT_TABLE)
        return True
    detail = (r.stderr or r.stdout or "").strip()
    if "no such table" in detail.lower() or "has no table" in detail.lower():
        if not expect_absent:
            log.debug("host nft table %s already absent", NFT_TABLE)
        return True
    log.warning("nft delete table %s rc=%d: %s", NFT_TABLE, r.returncode, detail[:200])
    return False


def probe_uid_matches(user: str = HOST_PROBE_USER) -> bool:
    """True when the probe uid exists AND is not nobody/overflow-uid (§8)."""
    import pwd

    try:
        entry = pwd.getpwnam(user)
    except KeyError:
        return False
    # 65534=nobody, 2147483647=overflow-uid (nfqws2 after setuid) — never use.
    return entry.pw_uid not in (65534, 2147483647)


def self_check() -> list[str]:
    """Resolver pre-flight errors for probe-isol=host (§12). Empty list = OK."""
    errors: list[str] = []
    if not nft_available():
        errors.append("nft not available in PATH")
    if not probe_uid_matches():
        errors.append(
            f"probe uid {HOST_PROBE_USER!r} missing or forbidden (nobody/overflow-uid)"
        )
    return errors


__all__ = [
    "NFT_TABLE",
    "queue_bound",
    "attach_host_queue",
    "build_notrack_rule",
    "build_queue_rules",
    "nft_available",
    "probe_uid_matches",
    "qnum_busy",
    "self_check",
    "table_exists",
    "teardown_host_queue",
]
