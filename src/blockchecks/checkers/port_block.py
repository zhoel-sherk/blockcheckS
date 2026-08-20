"""TCP port reachability on resolved IPs."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field


@dataclass
class PortProbe:
    ip: str
    port: int
    reachable: bool
    latency_ms: float = 0.0
    error: str = ""


@dataclass
class PortBlockReport:
    domain: str
    port: int
    probes: list[PortProbe] = field(default_factory=list)

    @property
    def all_reachable(self) -> bool:
        return bool(self.probes) and all(p.reachable for p in self.probes)

    @property
    def any_reachable(self) -> bool:
        return any(p.reachable for p in self.probes)


def probe_tcp_port(ip: str, port: int, timeout: float = 3.0) -> PortProbe:
    """Try TCP connect to ip:port (no TLS)."""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return PortProbe(
                ip=ip,
                port=port,
                reachable=True,
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
    except OSError as e:
        return PortProbe(
            ip=ip,
            port=port,
            reachable=False,
            latency_ms=(time.perf_counter() - t0) * 1000,
            error=str(e)[:120],
        )


def run_port_block_probe(
    domain: str,
    ips: list[str],
    port: int = 443,
    timeout: float = 3.0,
) -> PortBlockReport:
    """Probe all resolved IPs for TCP port reachability."""
    report = PortBlockReport(domain=domain, port=port)
    for ip in ips[:10]:
        report.probes.append(probe_tcp_port(ip, port, timeout=timeout))
    return report


def print_port_block_report(report: PortBlockReport) -> None:
    print(f"\n  Port block probe: {report.domain}:{report.port}")
    if not report.probes:
        print("  No IPs to probe")
        return
    for p in report.probes:
        tag = "OK" if p.reachable else "FAIL"
        err = f" ({p.error})" if p.error else ""
        print(f"    [{tag}] {p.ip}:{p.port}  {p.latency_ms:.0f}ms{err}")
