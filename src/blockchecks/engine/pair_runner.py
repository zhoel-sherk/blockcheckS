"""Pair test runner — TCP×UDP matrix with checkpoint/resume.

Flow:
  1. Load TCP + UDP configs
  2. If --resume: skip to checkpoint (tcp_idx, udp_idx)
  3. TCP phase: test each TCP config, save results
  4. For each PASS TCP (or all if --udp-bypass):
     a. Start TCP nfqws2 (keep alive)
     b. For each UDP config:
        - Start/switch UDP nfqws2
        - UDP probe (STUN or IP discovery)
        - If --full-voice: gateway WS + voice handshake
        - Save checkpoint
     c. Output pair matrix
  5. Stop both, export results
"""

import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

# Colorama for colored output
from colorama import Fore, Style, init as colorama_init
colorama_init(autoreset=True)

from blockchecks.engine.pair_manager import DualNfqws2Manager
from blockchecks.engine.db_logger import StateDB

GREEN = Fore.GREEN + Style.BRIGHT
RED = Fore.RED + Style.BRIGHT
GREY = Fore.LIGHTBLACK_EX
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
RESET = Style.RESET_ALL


@dataclass
class TcpTestResult:
    config: str
    name: str
    domain: str
    success: bool = False
    http_code: int = 0
    latency_ms: float = 0
    content_valid: bool = True
    gateway_ms: float = 0
    error: str = ""


@dataclass
class UdpTestResult:
    config: str
    name: str
    target: str
    success: bool = False
    latency_ms: float = 0
    error: str = ""


@dataclass
class PairResult:
    tcp_config: str
    udp_config: str
    tcp_ok: bool = False
    gateway_ok: bool = False
    udp_ok: bool = False
    tcp_ms: float = 0
    gateway_ms: float = 0
    udp_ms: float = 0
    overall: str = "PENDING"  # PASS, PARTIAL, FAIL


@dataclass
class PairReport:
    domain: str
    tcp_results: list[TcpTestResult] = field(default_factory=list)
    udp_results: list[UdpTestResult] = field(default_factory=list)
    pairs: list[PairResult] = field(default_factory=list)
    total_time_sec: float = 0
    voice_info: dict = field(default_factory=dict)


class PairTestRunner:
    """Run TCP×UDP pair matrix testing."""

    def __init__(self, ns_name: Optional[str] = None,
                 db_path: str = "state.db"):
        self.ns_name = ns_name
        self.db = StateDB(db_path)
        self._python = sys.executable

    def _run_curl_check(self, domain: str, timeout: float,
                         check_gateway: bool = False) -> dict:
        """Run curl_cffi TLS check via subprocess."""
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
        allow_redirects=False,
    )
    body = resp.content[:4096]
    content_len = len(resp.content)
    content_ok = content_len >= 2000
    dpi_fake = any(p in body.lower() for p in (b"blocked", b"rkn", b"forbidden", b"access denied"))
    if dpi_fake:
        content_ok = False
    result = {{
        "success": 200 <= resp.status_code < 400 and content_ok,
        "http_code": resp.status_code,
        "latency_ms": (time.perf_counter() - start) * 1000,
        "content_len": content_len,
        "content_ok": content_ok,
        "error": None,
    }}
except curl_cffi.CurlError as e:
    msg = str(e)
    result = {{"success": False, "http_code": 0,
               "latency_ms": (time.perf_counter() - start) * 1000,
               "content_len": 0, "content_ok": False,
               "error": "timeout" if "Timeout" in msg else msg[:120]}}
except Exception as e:
    result = {{"success": False, "http_code": 0, "latency_ms": 0,
               "content_len": 0, "content_ok": False, "error": str(e)[:120]}}
print(json.dumps(result))
"""
        if self.ns_name:
            cmd = ["sudo", "ip", "netns", "exec", self.ns_name,
                   self._python, "-c", code]
        else:
            cmd = ["sudo", self._python, "-c", code]

        import subprocess
        r = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout + 10)
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            return {"success": False, "http_code": 0, "latency_ms": 0,
                    "content_len": 0, "content_ok": False,
                    "error": f"parse: {r.stdout[:100]}"}

    def _run_stun_check(self, ip: str, port: int, timeout: float) -> dict:
        """Run dual voice UDP probe via subprocess."""
        code = f"""
import json
from blockchecks.checkers.udp_voice import voice_udp_probe
ok, lat, detail, method = voice_udp_probe("{ip}", {port}, {timeout})
print(json.dumps({{"success": ok, "latency_ms": round(lat, 1),
                   "detail": detail, "method": method}}))
"""
        if self.ns_name:
            cmd = ["sudo", "ip", "netns", "exec", self.ns_name,
                   self._python, "-c", code]
        else:
            cmd = ["sudo", self._python, "-c", code]

        import subprocess
        r = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout + 5)
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            return {"success": False, "latency_ms": 0, "detail": "parse error"}

    async def test_tcp_matrix(self, tcp_configs: list[str], domain: str,
                               timeout: float = 5.0) -> list[TcpTestResult]:
        """Test each TCP config against domain. Returns results."""
        results = []
        import os
        for config in tcp_configs:
            name = os.path.basename(config).replace(".conf", "")
            result = TcpTestResult(config=config, name=name, domain=domain)

            # Start nfqws2 temporarily for this test
            mgr = DualNfqws2Manager(ns_name=self.ns_name)
            try:
                mgr.start_tcp(config)
                data = self._run_curl_check(domain, timeout)
                result.success = data.get("success", False)
                result.http_code = data.get("http_code", 0)
                result.latency_ms = data.get("latency_ms", 0)
                result.content_valid = data.get("content_ok", False)
                result.error = data.get("error", "") or ""

                tag = f"{GREEN}OK{RESET}" if result.success else f"{RED}FAIL{RESET}"
                status = f"HTTP {result.http_code}" if result.http_code else ""
                lat = f"{result.latency_ms:.0f}ms" if result.latency_ms else ""
                err = f" — {result.error[:40]}" if result.error else ""
                print(f"  [{tag}] {lat:>6s}  {status:>8s}  TCP {name}{err}")

                await self.db.log_tcp(
                    name, domain,
                    "PASS" if result.success else "FAIL",
                    result.latency_ms, result.http_code,
                    content_valid=result.content_valid,
                    error=result.error
                )
            except Exception as e:
                result.error = str(e)[:120]
                print(f"  [{RED}FAIL{RESET}]        {GREY}ERR{RESET}    TCP {name} — {e}")
            finally:
                mgr.stop()

            results.append(result)
        return results

    async def test_pair_matrix(self,
                                tcp_configs: list[str],
                                udp_configs: list[str],
                                domain: str,
                                tcp_results: list[TcpTestResult],
                                voice_ip: str = "35.217.5.42",
                                voice_port: int = 50006,
                                udp_timeout: float = 3.0,
                                udp_bypass: bool = False,
                                resume_from: Optional[tuple] = None
                                ) -> PairReport:
        """Run TCP×UDP pair matrix against voice server.

        For each PASS TCP (or all if --udp-bypass):
          Start TCP nfqws2, keep alive
          For each UDP config: switch UDP nfqws2, probe
           Save checkpoint after each pair.
        """
        t0_f = time.perf_counter()
        report = PairReport(domain=domain,
                            tcp_results=tcp_results,
                            voice_info={"ip": voice_ip, "port": voice_port})

        import os

        # Filter working TCP configs
        if udp_bypass:
            working_tcp = [(c, r) for c, r in zip(tcp_configs, tcp_results)]
        else:
            working_tcp = [
                (c, r) for c, r in zip(tcp_configs, tcp_results)
                if r.success
            ]

        if not working_tcp:
            print(f"\n  {RED}No PASS TCP strategies — UDP tests skipped{RESET}")
            print(f"  Use --udp-bypass to force UDP tests on FAIL TCP strategies.")
            return report

        total_pairs = len(working_tcp) * len(udp_configs)
        pair_count = 0

        # Apply resume checkpoint
        start_tcp_idx = 0
        start_udp_idx = 0
        if resume_from:
            start_tcp_idx, start_udp_idx, *_ = resume_from
            print(f"\n  {YELLOW}Resuming from checkpoint: tcp={start_tcp_idx} udp={start_udp_idx}{RESET}")

        for tcp_i, (tcp_conf, tcp_r) in enumerate(working_tcp):
            if tcp_i < start_tcp_idx:
                continue

            tcp_name = os.path.basename(tcp_conf).replace(".conf", "")
            mgr = DualNfqws2Manager(ns_name=self.ns_name)

            try:
                # Start TCP nfqws2 — keep alive across all UDP scans
                mgr.start_tcp(tcp_conf)
                time.sleep(0.5)

                for udp_i, udp_conf in enumerate(udp_configs):
                    if tcp_i == start_tcp_idx and udp_i < start_udp_idx:
                        continue

                    udp_name = os.path.basename(udp_conf).replace(".conf", "")
                    pair_count += 1

                    # Start or switch UDP instance
                    if pair_count == 1 or tcp_i > start_tcp_idx or udp_i > start_udp_idx:
                        if mgr._udp_proc:
                            mgr.switch_udp(udp_conf)
                        else:
                            mgr.start_udp(udp_conf)
                    time.sleep(0.3)

                    # UDP probe
                    target = f"{voice_ip}:{voice_port}"
                    data = self._run_stun_check(voice_ip, voice_port, udp_timeout)
                    udp_ok = data.get("success", False)
                    udp_ms = data.get("latency_ms", 0)

                    pair = PairResult(
                        tcp_config=tcp_name,
                        udp_config=udp_name,
                        tcp_ok=tcp_r.success,
                        udp_ok=udp_ok,
                        tcp_ms=tcp_r.latency_ms,
                        udp_ms=udp_ms,
                    )

                    # Overall verdict
                    if tcp_r.success and udp_ok:
                        pair.overall = "PASS"
                        pair_tag = f"{GREEN}PASS{RESET}"
                    elif tcp_r.success and not udp_ok:
                        pair.overall = "PARTIAL"
                        pair_tag = f"{YELLOW}PARTIAL{RESET}"
                    else:
                        pair.overall = "FAIL"
                        pair_tag = f"{RED}FAIL{RESET}"

                    udp_tag = f"{GREEN}{udp_ms:.0f}ms{RESET}" if udp_ok else f"{RED}timeout{RESET}"
                    err = f" — {data.get('detail', '')}" if not udp_ok else ""
                    print(f"  [{pair_tag}] TCP={tcp_name[:25]:25s}  "
                          f"UDP={udp_name[:25]:25s}  "
                          f"udp={udp_tag}{err}")

                    report.pairs.append(pair)

                    # Log to DB
                    await self.db.log_udp(udp_name, target,
                                          "PASS" if udp_ok else "FAIL",
                                          udp_ms, data.get("detail", ""))
                    await self.db.log_pair(
                        tcp_name, udp_name, domain,
                        tcp_r.success, False, udp_ok,  # gateway_ok=False for now
                        tcp_r.latency_ms, 0, udp_ms, pair.overall
                    )

                    # Save checkpoint after every pair
                    await self.db.save_checkpoint(
                        tcp_i, udp_i,
                        f"{tcp_name}+{udp_name}",
                        tcp_label=tcp_name, udp_label=udp_name,
                    )

            finally:
                mgr.stop()

        report.total_time_sec = time.perf_counter() - t0_f
        return report

    def print_matrix(self, report: PairReport):
        """Print colored pair matrix."""
        if not report.pairs:
            return

        tcp_names = sorted(set(p.tcp_config for p in report.pairs))
        udp_names = sorted(set(p.udp_config for p in report.pairs))
        pair_map = {f"{p.tcp_config}|{p.udp_config}": p for p in report.pairs}

        print(f"\n  {CYAN}╔{'═'*70}╗{RESET}")
        print(f"  {CYAN}║{'TCP×UDP Pair Matrix':^70s}║{RESET}")
        print(f"  {CYAN}╠{'═'*30}╦{'═'*39}╣{RESET}")

        header = "  ║ TCP Strategy".ljust(32) + "║ UDP Strategy".ljust(41) + "║"
        print(f"{CYAN}{header}{RESET}")
        print(f"  {CYAN}╠{'═'*30}╬{'═'*39}╣{RESET}")

        passed = 0
        for tcp in tcp_names:
            for udp in udp_names:
                p = pair_map.get(f"{tcp}|{udp}")
                if not p:
                    continue
                if p.overall == "PASS":
                    passed += 1
                    tag = f"{GREEN}PASS{RESET}"
                elif p.overall == "PARTIAL":
                    tag = f"{YELLOW}PARTIAL{RESET}"
                else:
                    tag = f"{RED}FAIL{RESET}"

                udp_lat = f"{p.udp_ms:.0f}ms" if p.udp_ok else "timeout"
                print(f"  ║ {tcp[:28]:28s} ║ {udp[:28]:28s} {tag:8s} udp={udp_lat:>8s} ║")

        print(f"  {CYAN}╚{'═'*30}╩{'═'*39}╝{RESET}")
        print(f"  {GREEN}{passed} PASS{RESET} / {len(report.pairs)} pairs")