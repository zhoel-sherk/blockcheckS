"""Firewall management — iptables OUTPUT NFQUEUE for nfqws2.

Phase 1: iptables (simple, one worker).
Phase 2: nftables vmap (O(1) dispatch, N workers).
"""

import subprocess
from typing import Optional


class Firewall:
    """Manage iptables NFQUEUE rules for strategy testing."""

    def __init__(self, ns_name: Optional[str] = None):
        self.ns_name = ns_name
        self._rules_added = False

    def _run(self, *args: str, check: bool = False) -> subprocess.CompletedProcess:
        """Run iptables command, optionally inside a network namespace."""
        cmd = ["sudo"]
        if self.ns_name:
            cmd.extend(["ip", "netns", "exec", self.ns_name])
        cmd.extend(["iptables"] + list(args))
        result = subprocess.run(cmd, capture_output=True, text=True)
        if check and result.returncode != 0:
            raise RuntimeError(f"iptables failed: {result.stderr[:200]}")
        return result

    def prepare_tcp(self, port: int = 443, qnum: int = 200,
                    dst_ip: Optional[str] = None) -> None:
        """Add OUTPUT NFQUEUE rule for TCP traffic.

        Args:
            port: destination TCP port
            qnum: NFQUEUE queue number (must match nfqws2 --qnum)
            dst_ip: optional destination IP filter (e.g., '162.159.128.233')
        """
        if dst_ip:
            self._run("-A", "OUTPUT", "-p", "tcp", "--dport", str(port),
                      "-d", dst_ip, "-j", "NFQUEUE", "--queue-num", str(qnum),
                      check=True)
        else:
            self._run("-A", "OUTPUT", "-p", "tcp", "--dport", str(port),
                      "-j", "NFQUEUE", "--queue-num", str(qnum),
                      check=True)
        self._rules_added = True

    def prepare_udp(self, ports: str = "50000:50100", qnum: int = 200) -> None:
        """Add OUTPUT NFQUEUE rule for UDP traffic.

        Args:
            ports: port range (e.g., '50000:50100' or '50004')
            qnum: NFQUEUE queue number
        """
        if ":" in ports:
            self._run("-A", "OUTPUT", "-p", "udp", "-m", "multiport",
                      "--dports", ports, "-j", "NFQUEUE",
                      "--queue-num", str(qnum), check=True)
        else:
            self._run("-A", "OUTPUT", "-p", "udp", "--dport", ports,
                      "-j", "NFQUEUE", "--queue-num", str(qnum),
                      check=True)
        self._rules_added = True

    def cleanup(self) -> None:
        """Remove all NFQUEUE rules from OUTPUT chain."""
        if not self._rules_added:
            return
        self._run("-F", "OUTPUT")
        self._rules_added = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cleanup()
