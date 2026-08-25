"""Netns and iptables helpers for a lua-bridge session."""

from __future__ import annotations

from blockchecks.engine.config import NFQUEUE_TCP, NFQUEUE_UDP


class NetnsGoneError(RuntimeError):
    """Netns was destroyed while in use by another process."""


class IptablesError(RuntimeError):
    """NFQUEUE rule missing — probes would bypass nfqws2 (false PASS)."""


def _check_netns_exists(ns_name: str) -> None:
    import subprocess as sp

    r = sp.run(
        ["sudo", "ip", "netns", "list"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    for line in r.stdout.splitlines():
        if line.strip() == ns_name or line.strip().startswith(ns_name + " "):
            return
    raise NetnsGoneError(
        f"netns {ns_name!r} no longer exists — pool may have been destroyed "
        f"by a concurrent process. Retry or restart the scan."
    )


def _netns_tcp_probe_cleanup(ns_name: str) -> None:
    """Drop nfqws2 + flush OUTPUT iptables after classic per-probe runs."""
    import subprocess as sp

    from blockchecks.service.metrics import pkill_nfqws2_in_ns

    pkill_nfqws2_in_ns(ns_name)
    sp.run(
        ["sudo", "ip", "netns", "exec", ns_name, "iptables", "-F", "OUTPUT"],
        capture_output=True,
        check=False,
        timeout=15,
    )


def _bridge_iptables_add(ns_name: str, dport: str, protocol: str = "tls12") -> None:
    import logging
    import subprocess as sp

    _log = logging.getLogger("blockchecks.lua_netns")
    is_quic = protocol == "quic"
    _check_netns_exists(ns_name)
    qnum = NFQUEUE_UDP if is_quic else NFQUEUE_TCP
    base = [
        "sudo",
        "ip",
        "netns",
        "exec",
        ns_name,
        "iptables",
    ]
    flush = sp.run(
        base + ["-F", "OUTPUT"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if flush.returncode != 0:
        _log.warning(
            "%s",
            f"  [iptables] {ns_name}: -F OUTPUT failed rc={flush.returncode} "
            f"stderr={flush.stderr.strip()!r}",
        )
    add = sp.run(
        [
            *base,
            "-A",
            "OUTPUT",
            "-p",
            "udp" if is_quic else "tcp",
            "--dport",
            dport,
            "-j",
            "NFQUEUE",
            "--queue-num",
            str(qnum),
            "--queue-bypass",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if add.returncode != 0:
        _log.warning(
            "%s",
            f"  [iptables] {ns_name}: -A NFQUEUE/{qnum} FAILED rc={add.returncode} "
            f"stderr={add.stderr.strip()!r} stdout={add.stdout.strip()!r}",
        )
        raise IptablesError(
            f"{ns_name}: iptables -A NFQUEUE/{qnum} failed rc={add.returncode}"
        )
    # Верификация: правило обязано существовать после успешного -A
    verify = sp.run(
        base
        + [
            "-C",
            "OUTPUT",
            "-p",
            "udp" if is_quic else "tcp",
            "--dport",
            dport,
            "-j",
            "NFQUEUE",
            "--queue-num",
            str(qnum),
            "--queue-bypass",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if verify.returncode != 0:
        _log.warning(
            "%s",
            f"  [iptables] {ns_name}: rule MISSING right after -A "
            f"(rc={verify.returncode}) — что-то сбрасывает таблицу",
        )
        raise IptablesError(
            f"{ns_name}: iptables -C NFQUEUE/{qnum} failed after -A"
        )
