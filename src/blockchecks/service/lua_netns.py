"""Netns and iptables helpers for a lua-bridge session."""

from __future__ import annotations

from blockchecks.engine.config import NFQUEUE_TCP, NFQUEUE_UDP
from blockchecks.service.ns_firewall import (
    IptablesError,
    get_ns_firewall,
    mark_ns_dirty,
)

__all__ = [
    "IptablesError",
    "NetnsGoneError",
    "_bridge_iptables_add",
    "_check_netns_exists",
    "_netns_tcp_probe_cleanup",
]


class NetnsGoneError(RuntimeError):
    """Netns was destroyed while in use by another process."""


def _check_netns_exists(ns_name: str) -> None:
    import subprocess as sp

    r = sp.run(
        ["sudo", "-n", "ip", "netns", "list"],
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
    """Drop nfqws2 and tracked NFQUEUE rules after classic per-probe runs."""
    from blockchecks.service.metrics import pkill_nfqws2_in_ns

    pkill_nfqws2_in_ns(ns_name)
    mark_ns_dirty(ns_name)
    get_ns_firewall(ns_name).detach()


def _bridge_iptables_add(ns_name: str, dport: str, protocol: str = "tls12") -> None:
    _check_netns_exists(ns_name)
    is_quic = protocol == "quic"
    qnum = NFQUEUE_UDP if is_quic else NFQUEUE_TCP
    proto = "udp" if is_quic else "tcp"
    get_ns_firewall(ns_name).attach(proto=proto, port=dport, queue=qnum)
