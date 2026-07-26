"""Test runner — sequential strategy testing (Phase 1 + UDP voice Phase 3)."""

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from engine.firewall import Firewall
from engine.nfqws2 import Nfqws2Manager


@dataclass
class StrategyResult:
    strategy: str
    domain: str
    success: bool = False
    latency_ms: float = 0.0
    http_status: int = 0
    error: Optional[str] = None
    time_total_ms: float = 0.0


@dataclass
class ScanReport:
    domain: str
    protocol: str
    results: list[StrategyResult] = field(default_factory=list)
    total_time_sec: float = 0.0

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.success)


def _check_tls_in_ns(domain: str, timeout: float) -> dict:
    """Run curl_cffi check and return result as dict."""
    code = f"""
import json, time, sys
try:
    import curl_cffi
    start = time.perf_counter()
    resp = curl_cffi.get(
        "https://{domain}",
        impersonate="chrome124",
        http_version=2,
        timeout={timeout},
        headers={{"Accept": "text/html"}},
    )
    result = {{
        "success": 200 <= resp.status_code < 400,
        "http_status": resp.status_code,
        "latency_ms": (time.perf_counter() - start) * 1000,
        "error": None,
    }}
except curl_cffi.CurlError as e:
    msg = str(e)
    result = {{
        "success": False,
        "http_status": 0,
        "latency_ms": (time.perf_counter() - start) * 1000,
        "error": "timeout" if "Timeout" in msg else (msg[:120]),
    }}
except Exception as e:
    result = {{"success": False, "http_status": 0, "latency_ms": 0, "error": str(e)[:120]}}
print(json.dumps(result))
"""
    return {"domain": domain, "code": code}


class TestRunner:
    """Run DPI bypass strategies against domains.

    Phase 1 (MVP): Sequential — one strategy, one domain, one test.
    Phase 2: Parallel — multiple strategies via asyncio.
    """

    def __init__(self, ns_name: Optional[str] = None):
        self.ns_name = ns_name
        self._python = sys.executable  # use same Python that runs the tester

    def _run_check(self, domain: str, timeout: float) -> StrategyResult:
        """Run curl_cffi check inside namespace (or main ns if no netns)."""
        info = _check_tls_in_ns(domain, timeout)
        code = info["code"]

        if self.ns_name:
            cmd = ["sudo", "ip", "netns", "exec", self.ns_name,
                   self._python, "-c", code]
        else:
            cmd = [self._python, "-c", code]

        r = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout + 5)

        result = StrategyResult(strategy="", domain=domain)
        try:
            data = json.loads(r.stdout)
            result.success = data.get("success", False)
            result.http_status = data.get("http_status", 0)
            result.latency_ms = data.get("latency_ms", 0)
            result.error = data.get("error")
        except json.JSONDecodeError:
            result.error = f"parse error: {r.stdout[:100]}"

        return result

    def test_single(self, strategy: str, domain: str,
                    timeout: float = 3.0,
                    hostlist: Optional[list[str]] = None,
                    qnum: int = 200) -> StrategyResult:
        """Test a single strategy string against a single domain."""
        result = StrategyResult(strategy=strategy, domain=domain)
        t0 = time.perf_counter()

        fw = Firewall(ns_name=self.ns_name)
        nfqws2 = Nfqws2Manager(ns_name=self.ns_name)

        try:
            fw.prepare_tcp(qnum=qnum)
            nfqws2.start(strategy, hostlist=hostlist, qnum=qnum)

            check = self._run_check(domain, timeout)
            result.success = check.success
            result.latency_ms = check.latency_ms
            result.http_status = check.http_status
            result.error = check.error
        except Exception as e:
            result.error = str(e)[:200]
        finally:
            nfqws2.stop()
            fw.cleanup()

        result.time_total_ms = (time.perf_counter() - t0) * 1000
        return result

    def test_config(self, config_path: str, domain: str,
                    timeout: float = 3.0, qnum: int = 200) -> StrategyResult:
        """Test a pre-built nfqws2 .conf file against a domain."""
        import os
        basename = os.path.basename(config_path).replace(".conf", "")
        result = StrategyResult(strategy=basename, domain=domain)
        t0 = time.perf_counter()

        fw = Firewall(ns_name=self.ns_name)
        nfqws2 = Nfqws2Manager(ns_name=self.ns_name)

        try:
            fw.prepare_tcp(qnum=qnum)
            nfqws2.start_config(config_path)

            check = self._run_check(domain, timeout)
            result.success = check.success
            result.latency_ms = check.latency_ms
            result.http_status = check.http_status
            result.error = check.error
        except Exception as e:
            result.error = str(e)[:200]
        finally:
            nfqws2.stop()
            fw.cleanup()

        result.time_total_ms = (time.perf_counter() - t0) * 1000
        return result

    def test_sequential(self, strategies: list[str], domain: str,
                        timeout: float = 3.0,
                        hostlist: Optional[list[str]] = None,
                        qnum: int = 200) -> ScanReport:
        """Test multiple strategies against one domain sequentially."""
        report = ScanReport(domain=domain, protocol="tls")
        t0 = time.perf_counter()

        for strategy in strategies:
            r = self.test_single(strategy, domain, timeout=timeout,
                                 hostlist=hostlist, qnum=qnum)
            report.results.append(r)

            tag = "OK" if r.success else "FAIL"
            status = f"HTTP {r.http_status}" if r.http_status else ""
            err = f" — {r.error[:60]}" if r.error else ""
            print(f"  [{tag}] {r.latency_ms:6.0f}ms  {status}  "
                  f"strategy={r.strategy[:70]}{err}")

        report.total_time_sec = time.perf_counter() - t0
        return report

    def test_sequential_configs(self, config_paths: list[str], domain: str,
                                timeout: float = 3.0,
                                qnum: int = 200) -> ScanReport:
        """Test multiple .conf files against one domain sequentially."""
        report = ScanReport(domain=domain, protocol="tls")
        t0 = time.perf_counter()

        for config_path in config_paths:
            r = self.test_config(config_path, domain, timeout=timeout,
                                 qnum=qnum)
            report.results.append(r)

            tag = "OK" if r.success else "FAIL"
            status = f"HTTP {r.http_status}" if r.http_status else ""
            err = f" — {r.error[:60]}" if r.error else ""
            print(f"  [{tag}] {r.latency_ms:6.0f}ms  {status}  "
                  f"config={r.strategy[:60]}{err}")

        report.total_time_sec = time.perf_counter() - t0
        return report

    # ── UDP Voice testing (Phase 3) ──────────────────────────

    def _run_stun_check(self, ip: str, port: int, timeout: float) -> dict:
        """Run STUN probe via subprocess (inside namespace if configured)."""
        code = f"""
import sys, json
sys.path.insert(0, "{os.path.dirname(os.path.dirname(__file__))}")
from checkers.udp_voice import stun_probe
ok, lat, detail = stun_probe("{ip}", {port}, {timeout})
print(json.dumps({{"success": ok, "latency_ms": round(lat, 1), "detail": detail}}))
"""
        if self.ns_name:
            cmd = ["sudo", "ip", "netns", "exec", self.ns_name,
                   self._python, "-c", code]
        else:
            cmd = [self._python, "-c", code]

        r = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout + 5)
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            return {"success": False, "latency_ms": 0.0,
                    "detail": f"parse error: {r.stdout[:100]}"}

    def test_udp_config(self, config_path: str, ip: str,
                        port: int = 50004, timeout: float = 3.0,
                        qnum: int = 201) -> StrategyResult:
        """Test a UDP nfqws2 config against a voice server IP."""
        basename = os.path.basename(config_path).replace(".conf", "")
        result = StrategyResult(strategy=basename, domain=f"{ip}:{port}")
        t0 = time.perf_counter()

        fw = Firewall(ns_name=self.ns_name)
        nfqws2 = Nfqws2Manager(ns_name=self.ns_name)

        try:
            fw.prepare_udp(ports=str(port), qnum=qnum)
            nfqws2.start_config(config_path)

            data = self._run_stun_check(ip, port, timeout)
            result.success = data.get("success", False)
            result.latency_ms = data.get("latency_ms", 0.0)
            result.error = data.get("detail", "") if not result.success else None
        except Exception as e:
            result.error = str(e)[:200]
        finally:
            nfqws2.stop()
            fw.cleanup()

        result.time_total_ms = (time.perf_counter() - t0) * 1000
        return result

    def test_sequential_udp(self, config_paths: list[str], ip: str,
                            port: int = 50004, timeout: float = 3.0,
                            qnum: int = 201) -> ScanReport:
        """Test multiple UDP configs against a voice server IP."""
        report = ScanReport(domain=f"{ip}:{port}", protocol="udp_voice")
        t0 = time.perf_counter()

        for config_path in config_paths:
            r = self.test_udp_config(config_path, ip, port=port,
                                     timeout=timeout, qnum=qnum)
            report.results.append(r)

            tag = "OK" if r.success else "FAIL"
            err = f" — {r.error[:60]}" if r.error else ""
            lat = f"{r.latency_ms:.0f}ms" if r.success else ""
            print(f"  [{tag}] {lat:>6s}  config={r.strategy[:55]}{err}")

        report.total_time_sec = time.perf_counter() - t0
        return report
