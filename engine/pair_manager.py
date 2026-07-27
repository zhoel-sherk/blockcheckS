"""Dual nfqws2 manager — two separate instances (TCP q200 + UDP q201).

Keeps TCP instance alive across UDP matrix scans.
UDP instance restarts per strategy via switch_udp().
"""

import os
import subprocess
import time
from typing import Optional

NFQWS2_BIN = "/opt/zapret2/nfq2/nfqws2"
TCP_QNUM = 200
UDP_QNUM = 201


class DualNfqws2Manager:
    """Manage two independent nfqws2 processes.

    TCP instance (qnum=200): stays alive during UDP matrix scan.
    UDP instance (qnum=201): restarts via switch_udp() per strategy.
    """

    def __init__(self, ns_name: Optional[str] = None):
        self.ns_name = ns_name
        self._tcp_proc: Optional[subprocess.Popen] = None
        self._udp_proc: Optional[subprocess.Popen] = None
        self._tcp_conf: Optional[str] = None
        self._udp_conf: Optional[str] = None

    def _ns_prefix(self) -> list[str]:
        if self.ns_name:
            return ["sudo", "ip", "netns", "exec", self.ns_name]
        return []

    def _run_iptables(self, *args: str) -> None:
        cmd = self._ns_prefix() + ["iptables"] + list(args)
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"iptables failed: {r.stderr[:200]}")

    def _start_nfqws2(self, config_path: str, label: str) -> subprocess.Popen:
        cmd = self._ns_prefix() + [NFQWS2_BIN, f"@{config_path}", "--daemon"]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.PIPE)
        time.sleep(1.0)

        check = self._ns_prefix() + ["pgrep", "-x", "nfqws2"]
        r = subprocess.run(check, capture_output=True, text=True)
        if r.returncode != 0:
            stderr = ""
            try:
                proc.wait(timeout=1)
                stderr = proc.stderr.read().decode() if proc.stderr else ""
            except Exception:
                pass
            raise RuntimeError(f"{label} nfqws2 failed: {stderr[:200]}")
        return proc

    def start_tcp(self, config_path: str) -> None:
        """Start TCP nfqws2 on qnum=200."""
        self._tcp_conf = config_path
        self._run_iptables("-A", "OUTPUT", "-p", "tcp", "--dport", "443",
                           "-j", "NFQUEUE", "--queue-num", str(TCP_QNUM))
        self._tcp_proc = self._start_nfqws2(config_path, "TCP")
        print(f"[nfqws2] TCP PID {self._tcp_proc.pid} (qnum={TCP_QNUM})")

    def start_udp(self, config_path: str) -> None:
        """Start UDP nfqws2 on qnum=201."""
        self._udp_conf = config_path
        self._run_iptables("-A", "OUTPUT", "-p", "udp", "-m", "multiport",
                           "--dports", "50000:50100",
                           "-j", "NFQUEUE", "--queue-num", str(UDP_QNUM))
        self._udp_proc = self._start_nfqws2(config_path, "UDP")
        print(f"[nfqws2] UDP PID {self._udp_proc.pid} (qnum={UDP_QNUM})")

    def start_pair(self, tcp_conf: str, udp_conf: str) -> None:
        """Start both instances."""
        self.start_tcp(tcp_conf)
        self.start_udp(udp_conf)

    def switch_udp(self, new_udp_conf: str) -> None:
        """Restart only UDP instance with new config. TCP stays alive."""
        if self._udp_proc:
            try:
                self._udp_proc.terminate()
                self._udp_proc.wait(timeout=3)
            except Exception:
                self._udp_proc.kill()
            self._udp_proc = None

        # Keep iptables rules (port range doesn't change)
        self._udp_conf = new_udp_conf
        self._udp_proc = self._start_nfqws2(new_udp_conf, "UDP")
        print(f"[nfqws2] UDP switched → PID {self._udp_proc.pid}")

    def stop(self) -> None:
        """Kill both instances, flush iptables."""
        # Kill nfqws2 processes
        kill_cmd = self._ns_prefix() + ["pkill", "-9", "nfqws2"]
        subprocess.run(kill_cmd, capture_output=True, timeout=5)

        for p in [self._tcp_proc, self._udp_proc]:
            if p:
                try:
                    p.wait(timeout=3)
                except Exception:
                    pass

        self._tcp_proc = None
        self._udp_proc = None

        # Flush iptables
        flush_cmd = self._ns_prefix() + ["iptables", "-F", "OUTPUT"]
        subprocess.run(flush_cmd, capture_output=True, timeout=5)
        print("[nfqws2] Both instances stopped")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stop()
