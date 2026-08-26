"""Add and delete the iptables NFQUEUE rules this process created.
Always --queue-bypass. Never iptables -F OUTPUT.
"""

import logging
import subprocess

log = logging.getLogger(__name__)


class Firewall:
    """Manage iptables NFQUEUE rules for strategy testing.

    Stores each added rule as a list of iptables arguments.
    cleanup() removes them precisely via iptables -D.
    """

    def __init__(self, ns_name: str | None = None):
        self.ns_name = ns_name
        self._rules: list[list[str]] = []

    def _ns_prefix(self) -> list[str]:
        if self.ns_name:
            return ["sudo", "ip", "netns", "exec", self.ns_name]
        return ["sudo"]

    def _run(self, *args: str, check: bool = False) -> subprocess.CompletedProcess:
        """Run single iptables command."""
        cmd = self._ns_prefix() + ["iptables"] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True)
        if check and result.returncode != 0:
            raise RuntimeError(f"iptables: {result.stderr[:200]}")
        return result

    def _add_rule(self, *args: str) -> None:
        """Add a rule and track it for cleanup."""
        self._run("-A", *args, check=True)
        self._rules.append(["-D"] + list(args))

    def prepare_tcp(self, port: int = 443, qnum: int = 200, dst_ip: str | None = None) -> None:
        """Add OUTPUT NFQUEUE rule for TCP with queue-bypass."""
        if dst_ip:
            self._add_rule(
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-d",
                dst_ip,
                "-j",
                "NFQUEUE",
                "--queue-num",
                str(qnum),
                "--queue-bypass",
            )
        else:
            self._add_rule(
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-j",
                "NFQUEUE",
                "--queue-num",
                str(qnum),
                "--queue-bypass",
            )

    def prepare_udp(
        self, ports: str = "50000:50100", qnum: int = 200, voice_port: int = None
    ) -> None:
        """Add OUTPUT NFQUEUE rule for UDP with queue-bypass.

        If voice_port is set, queue that single port (Discord voice).
        """
        if voice_port is not None:
            ports = str(voice_port)
        if ":" in ports:
            self._add_rule(
                "OUTPUT",
                "-p",
                "udp",
                "--dport",
                ports,
                "-j",
                "NFQUEUE",
                "--queue-num",
                str(qnum),
                "--queue-bypass",
            )
        else:
            self._add_rule(
                "OUTPUT",
                "-p",
                "udp",
                "--dport",
                ports,
                "-j",
                "NFQUEUE",
                "--queue-num",
                str(qnum),
                "--queue-bypass",
            )

    def cleanup(self) -> None:
        """Remove only the rules we added via iptables -D (exception-safe)."""
        for rule_args in self._rules:
            try:
                self._run(*rule_args, check=False)
            except (OSError, subprocess.SubprocessError) as exc:
                log.warning(
                    "firewall cleanup: iptables delete failed %s: %s",
                    rule_args,
                    exc,
                )
        self._rules.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cleanup()
