"""Dual nfqws2 manager — two separate processes (TCP q200 + UDP q201).

Keeps TCP instance alive across UDP matrix scans.
UDP instance restarts via switch_udp() using killpg on owned PIDs.
"""

import os
import signal
import subprocess
import time
from typing import Optional

NFQWS2_BIN = "/opt/zapret2/nfq2/nfqws2"
TCP_QNUM = 200
UDP_QNUM = 201


class DualNfqws2Manager:
    """Manage two independent nfqws2 processes via foreground Popen + killpg."""

    def __init__(self, ns_name: Optional[str] = None):
        self.ns_name = ns_name
        self._tcp_proc: Optional[subprocess.Popen] = None
        self._udp_proc: Optional[subprocess.Popen] = None
        self._tcp_pid: Optional[int] = None
        self._udp_pid: Optional[int] = None
        self._rules: list[list[str]] = []

    def _ns_prefix(self) -> list[str]:
        if self.ns_name:
            return ["sudo", "ip", "netns", "exec", self.ns_name]
        return []

    def _add_iptables(self, *args: str) -> None:
        cmd = self._ns_prefix() + ["iptables", "-A"] + list(args)
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"iptables failed: {r.stderr[:200]}")
        self._rules.append(["-D"] + list(args))

    def _kill_by_pid(self, pid: Optional[int]) -> None:
        if pid is None:
            return
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            time.sleep(0.3)
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
        except (ProcessLookupError, OSError):
            pass

    def _start_nfqws2(self, config_path: str, label: str
                       ) -> subprocess.Popen:
        args = [NFQWS2_BIN, f"@{config_path}"]
        if self.ns_name:
            cmd = ["sudo", "ip", "netns", "exec", self.ns_name] + args
        else:
            cmd = ["sudo"] + args

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        time.sleep(0.8)

        if proc.poll() is not None:
            stderr = ""
            try:
                stderr = proc.stderr.read().decode()
            except Exception:
                pass
            raise RuntimeError(f"{label} nfqws2 failed: {stderr[:200]}")
        return proc

    def start_tcp(self, config_path: str) -> None:
        self._add_iptables("OUTPUT", "-p", "tcp", "--dport", "443",
                           "-j", "NFQUEUE", "--queue-num", str(TCP_QNUM),
                           "--queue-bypass")
        self._tcp_proc = self._start_nfqws2(config_path, "TCP")
        self._tcp_pid = self._tcp_proc.pid

    def start_udp(self, config_path: str, voice_port: int = 50006) -> None:
        port_str = str(voice_port)
        self._add_iptables("OUTPUT", "-p", "udp", "--dport", f"{port_str}:{port_str}",
                           "-j", "NFQUEUE", "--queue-num", str(UDP_QNUM),
                           "--queue-bypass")
        self._udp_proc = self._start_nfqws2(config_path, "UDP")
        self._udp_pid = self._udp_proc.pid

    def start_pair(self, tcp_conf: str, udp_conf: str,
                   voice_port: int = 50006) -> None:
        self.start_tcp(tcp_conf)
        self.start_udp(udp_conf, voice_port)

    def switch_udp(self, new_udp_conf: str, voice_port: int = 50006) -> None:
        self._kill_by_pid(self._udp_pid)
        if self._udp_proc:
            try:
                self._udp_proc.wait(timeout=3)
            except Exception:
                pass
            self._udp_proc = None
        self._udp_pid = None
        self._udp_proc = self._start_nfqws2(new_udp_conf, "UDP")
        self._udp_pid = self._udp_proc.pid

    def stop(self) -> None:
        self._kill_by_pid(self._tcp_pid)
        self._kill_by_pid(self._udp_pid)

        for p in [self._tcp_proc, self._udp_proc]:
            if p:
                try:
                    p.wait(timeout=3)
                except Exception:
                    try:
                        p.kill()
                        p.wait(timeout=2)
                    except Exception:
                        pass

        self._tcp_proc = None
        self._tcp_pid = None
        self._udp_proc = None
        self._udp_pid = None

        # Remove only our iptables rules
        for rule in reversed(self._rules):
            cmd = self._ns_prefix() + ["iptables"] + rule
            subprocess.run(cmd, capture_output=True, timeout=5)
        self._rules.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stop()
