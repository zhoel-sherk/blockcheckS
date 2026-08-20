"""Netns and iptables helpers for a lua-bridge session."""

from __future__ import annotations

from blockchecks.engine.config import NFQUEUE_TCP, NFQUEUE_UDP


class NetnsGoneError(RuntimeError):
    """Netns was destroyed while in use by another process."""


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

    sp.run(
        ["sudo", "ip", "netns", "exec", ns_name, "pkill", "-9", "nfqws2"],
        capture_output=True,
        check=False,
        timeout=15,
    )
    sp.run(
        ["sudo", "ip", "netns", "exec", ns_name, "iptables", "-F", "OUTPUT"],
        capture_output=True,
        check=False,
        timeout=15,
    )


def _bridge_iptables_add(ns_name: str, dport: str, protocol: str = "tls12") -> None:
    import subprocess as sp

    is_quic = protocol == "quic"
    _check_netns_exists(ns_name)
    sp.run(
        ["sudo", "ip", "netns", "exec", ns_name, "iptables", "-F", "OUTPUT"],
        capture_output=True,
        check=False,
        timeout=15,
    )
    sp.run(
        [
            "sudo",
            "ip",
            "netns",
            "exec",
            ns_name,
            "iptables",
            "-A",
            "OUTPUT",
            "-p",
            "udp" if is_quic else "tcp",
            "--dport",
            dport,
            "-j",
            "NFQUEUE",
            "--queue-num",
            str(NFQUEUE_UDP if is_quic else NFQUEUE_TCP),
            "--queue-bypass",
        ],
        capture_output=True,
        check=True,
        timeout=15,
    )
