"""Sequential strategy tests: one nfqws2, one domain, then optional UDP voice."""

import json
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field

from blockchecks.service.firewall import Firewall
from blockchecks.service.nfqws2 import Nfqws2Manager

log = logging.getLogger(__name__)


@dataclass
class StrategyResult:
    strategy: str
    domain: str
    success: bool = False
    latency_ms: float = 0.0
    http_status: int = 0
    error: str | None = None
    time_total_ms: float = 0.0


@dataclass
class ScanReport:
    domain: str
    protocol: str
    results: list[StrategyResult] = field(default_factory=list)
    total_time_sec: float = 0.0
    stopped_reason: str = ""

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.success)


def _check_tls_in_ns(domain: str, timeout: float, resolved_ip: str | None = None) -> dict:
    """Build curl probe payload for subprocess execution."""
    from blockchecks.checkers.curl_probe import build_probe_request

    req, err = build_probe_request(
        domain, timeout=timeout, resolved_ip=resolved_ip, protocol="tls12"
    )
    if err:
        return {"domain": domain, "payload": None, "error_result": err}
    return {
        "domain": domain,
        "payload": {
            "mode": "single",
            "request": {
                "domain": req.domain,
                "timeout": req.timeout,
                "resolved_ip": req.resolved_ip,
                "resolve_name": req.resolve_name,
                "curl_url": req.curl_url,
                "disable_ech": req.disable_ech,
                "googlevideo": req.googlevideo,
                "ggc": req.ggc,
                "protocol": req.protocol,
            },
            "repeats": 1,
            "parallel_repeats": False,
        },
        "error_result": None,
    }


class TestRunner:
    """Run one strategy against one domain in sequence. Parallel runs use AsyncTestRunner."""

    def __init__(
        self,
        ns_name: str | None = None,
        dns_cache=None,
        secure_dns: bool = True,
        repeats: int = 1,
        parallel_repeats: bool = False,
        repeats_mode: str = "fast",
        quick_break: bool = False,
    ):
        self.ns_name = ns_name
        self._python = sys.executable  # use same Python that runs the tester
        self.dns_cache = dns_cache
        self.secure_dns = secure_dns
        from blockchecks.checkers.curl_probe import clamp_repeats

        self.repeats = clamp_repeats(repeats)
        self.parallel_repeats = parallel_repeats
        self.repeats_mode = repeats_mode or "fast"
        self.quick_break = quick_break

    def _run_check(self, domain: str, timeout: float) -> StrategyResult:
        """Run curl probe inside namespace (or main ns if no netns)."""
        from blockchecks.checkers.curl_probe import worker_wall_timeout

        resolved_ip = None
        if self.secure_dns and self.dns_cache:
            resolved_ip = self.dns_cache.primary_ip(domain)
        info = _check_tls_in_ns(domain, timeout, resolved_ip=resolved_ip)
        if info.get("error_result"):
            data = info["error_result"]
            result = StrategyResult(strategy="", domain=domain)
            result.success = data.get("success", False)
            result.http_status = data.get("http_code", 0)
            result.latency_ms = data.get("latency_ms", 0)
            result.error = data.get("error")
            return result

        payload = json.dumps(info["payload"])
        probe = json.loads(payload)
        probe["repeats"] = self.repeats
        probe["parallel_repeats"] = bool(self.parallel_repeats and self.repeats > 1)
        probe["repeats_mode"] = self.repeats_mode
        probe["quick_break"] = self.quick_break
        payload = json.dumps(probe)
        if self.ns_name:
            cmd = [
                "sudo",
                "ip",
                "netns",
                "exec",
                self.ns_name,
                self._python,
                "-m",
                "blockchecks.service.in_ns_workers",
                "--mode",
                "curl",
            ]
        else:
            cmd = [
                self._python,
                "-m",
                "blockchecks.service.in_ns_workers",
                "--mode",
                "curl",
            ]

        wall = worker_wall_timeout(
            timeout,
            self.repeats,
            n_domains=1,
            curl_parallel=1,
            parallel_repeats=self.parallel_repeats,
            settle_slack=3.0,
        )
        r = subprocess.run(
            cmd,
            input=payload,
            capture_output=True,
            text=True,
            timeout=wall,
        )

        result = StrategyResult(strategy="", domain=domain)
        try:
            data = json.loads(r.stdout)
            result.success = data.get("success", False)
            result.http_status = data.get("http_code", 0)
            result.latency_ms = data.get("latency_ms", 0)
            result.error = data.get("error")
        except json.JSONDecodeError:
            result.error = f"parse error: {r.stdout[:100]}"

        return result

    def test_single(
        self,
        strategy: str,
        domain: str,
        timeout: float = 3.0,
        hostlist: list[str] | None = None,
        qnum: int = 200,
    ) -> StrategyResult:
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

    def test_config(
        self, config_path: str, domain: str, timeout: float = 3.0, qnum: int = 200
    ) -> StrategyResult:
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

    def test_sequential(
        self,
        strategies: list[str],
        domain: str,
        timeout: float = 3.0,
        hostlist: list[str] | None = None,
        qnum: int = 200,
        deadline=None,
    ) -> ScanReport:
        """Test multiple strategies against one domain sequentially."""
        report = ScanReport(domain=domain, protocol="tls")
        t0 = time.perf_counter()

        for strategy in strategies:
            if deadline is not None and deadline.expired_sync():
                report.stopped_reason = "time_limit"
                break
            r = self.test_single(strategy, domain, timeout=timeout, hostlist=hostlist, qnum=qnum)
            report.results.append(r)

            tag = "OK" if r.success else "FAIL"
            status = f"HTTP {r.http_status}" if r.http_status else ""
            err = f" — {r.error[:60]}" if r.error else ""
            log.info(
                "%s", f"  [{tag}] {r.latency_ms:6.0f}ms  {status}  strategy={r.strategy[:70]}{err}"
            )

        report.total_time_sec = time.perf_counter() - t0
        return report

    def test_sequential_configs(
        self,
        config_paths: list[str],
        domain: str,
        timeout: float = 3.0,
        qnum: int = 200,
        deadline=None,
    ) -> ScanReport:
        """Test multiple .conf files against one domain sequentially."""
        report = ScanReport(domain=domain, protocol="tls")
        t0 = time.perf_counter()

        for config_path in config_paths:
            if deadline is not None and deadline.expired_sync():
                report.stopped_reason = "time_limit"
                break
            r = self.test_config(config_path, domain, timeout=timeout, qnum=qnum)
            report.results.append(r)

            tag = "OK" if r.success else "FAIL"
            status = f"HTTP {r.http_status}" if r.http_status else ""
            err = f" — {r.error[:60]}" if r.error else ""
            log.info(
                "%s", f"  [{tag}] {r.latency_ms:6.0f}ms  {status}  config={r.strategy[:60]}{err}"
            )

        report.total_time_sec = time.perf_counter() - t0
        return report

    # UDP voice

    def _run_stun_check(self, ip: str, port: int, timeout: float) -> dict:
        """Run dual voice UDP probe via subprocess (inside namespace if configured)."""
        cmd = [
            self._python,
            "-m",
            "blockchecks.service.in_ns_workers",
            "--mode",
            "udp",
            ip,
            str(port),
            str(timeout),
        ]
        if self.ns_name:
            cmd = ["sudo", "ip", "netns", "exec", self.ns_name, *cmd]

        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 2 + 3)
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            return {"success": False, "latency_ms": 0.0, "detail": f"parse error: {r.stdout[:100]}"}

    def test_udp_config(
        self, config_path: str, ip: str, port: int = 50004, timeout: float = 3.0, qnum: int = 201
    ) -> StrategyResult:
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
        if result.success:
            import asyncio

            from blockchecks.service.in_ns_workers import _save_pass_strategy_data_block

            try:
                asyncio.run(
                    _save_pass_strategy_data_block(
                        config_path,
                        f"{ip}:{port}",
                        protocol="udp",
                        latency_ms=result.latency_ms,
                        http_code=0,
                    )
                )
            except Exception as exc:
                log.warning("%s", f"  WARNING: PASS upsert to data_block failed ({exc})")
        return result

    def test_sequential_udp(
        self,
        config_paths: list[str],
        ip: str,
        port: int = 50004,
        timeout: float = 3.0,
        qnum: int = 201,
    ) -> ScanReport:
        """Test multiple UDP configs against a voice server IP."""
        report = ScanReport(domain=f"{ip}:{port}", protocol="udp_voice")
        t0 = time.perf_counter()

        for config_path in config_paths:
            r = self.test_udp_config(config_path, ip, port=port, timeout=timeout, qnum=qnum)
            report.results.append(r)

            tag = "OK" if r.success else "FAIL"
            err = f" — {r.error[:60]}" if r.error else ""
            lat = f"{r.latency_ms:.0f}ms" if r.success else ""
            log.info("%s", f"  [{tag}] {lat:>6s}  config={r.strategy[:55]}{err}")

        report.total_time_sec = time.perf_counter() - t0
        return report
