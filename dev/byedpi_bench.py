#!/usr/bin/env python3
"""Standalone byedpi (ciadpi) vs nfqws2 selection-speed benchmark.

Runs the same set of nfqws2 strategies through:
  - baseline: blockcheckS `bs scan` (nfqws2 classic, per-strategy netns)
  - byedpi:   ciadpi SOCKS5 proxy per strategy + curl_cffi through socks5h

Measures test/sec and wall time. Uses dev/ (not installed) — run from repo.

Usage:
  python dev/byedpi_bench.py [--strategies N] [--domain discord.com]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("PYTHONUNBUFFERED", "1")

CIADPI = os.environ.get("CIADPI", str(Path.home() / "workspace/byedpi/ciadpi"))
BASE_PORT = int(os.environ.get("CIADPI_BASE_PORT", "18090"))

# nfqws2 strategy → ciadpi argv. Only the working slice (§3):
#   fake:blob=X:repeats=N:tcp_ts=-1000  →  -f -1 -l @X.bin -t 8
#   fakedsplit:pos=N:pattern=X          →  -f N -d N -l @X.bin
#   hostfakesplit:nofake2               →  --split 1+sm
STRATEGIES = [
    "fake:blob=stun:repeats=6:tcp_ts=-1000",
    "fake:blob=max_ru:repeats=6:tcp_ts=-1000",
    "fake:blob=google:repeats=6:tcp_ts=-1000",
    "fakedsplit:pos=1:pattern=stun:repeats=1",
    "hostfakesplit:nofake2:repeats=1",
]


def blob_path(name: str) -> str:
    from blockchecks.engine.blob_aliases import resolve_blob_path

    p = resolve_blob_path(name)
    if not p:
        raise SystemExit(f"no blob for {name!r}")
    return p


def to_ciadpi(strategy: str) -> list[str] | None:
    """Translate one nfqws2 strategy to ciadpi argv; None if unsupported."""
    if "blob=" in strategy and "tcp_ts=-1000" in strategy:
        blob = strategy.split("blob=")[1].split(":")[0]
        return ["-f", "-1", "-l", blob_path(blob), "-t", "8"]
    if strategy.startswith("fakedsplit:"):
        pos = "1"
        for part in strategy.split(":")[1:]:
            if part.startswith("pos="):
                pos = part.split("=")[1]
        blob = "stun"
        for part in strategy.split(":")[1:]:
            if part.startswith("pattern="):
                blob = part.split("=")[1]
        return ["-f", pos, "-d", pos, "-l", blob_path(blob)]
    if strategy.startswith("hostfakesplit:nofake2"):
        return ["--split", "1+sm"]
    return None


def bench_byedpi(strategies: list[str], domain: str) -> dict:
    """Run strategies via ciadpi SOCKS + curl_cffi; return timing stats."""
    import curl_cffi

    start = time.monotonic()
    results: list[tuple[str, bool, float]] = []
    procs: list[subprocess.Popen] = []
    try:
        for i, strat in enumerate(strategies):
            argv = to_ciadpi(strat)
            if argv is None:
                results.append((strat, False, -1.0))
                continue
            port = BASE_PORT + i
            cmd = [CIADPI, "-p", str(port), *argv]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(proc)
            time.sleep(0.05)
            t0 = time.monotonic()
            ok = False
            try:
                with curl_cffi.Session(impersonate="chrome124", timeout=5.0) as s:
                    r = s.get(
                        f"https://{domain}",
                        proxy=f"socks5h://127.0.0.1:{port}",
                    )
                    ok = 200 <= r.status_code < 400
            except Exception:
                ok = False
            results.append((strat, ok, time.monotonic() - t0))
            proc.terminate()
    finally:
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass
    total = time.monotonic() - start
    return {"total_s": total, "tests": len(results), "results": results}


def bench_nfqws2(strategies: list[str], domain: str) -> dict:
    """Baseline via `bs scan` (nfqws2 classic, per-strategy). Returns timing."""
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(strategies))
        matrix = f.name
    start = time.monotonic()
    r = subprocess.run(
        [
            "sudo", "-n", str(ROOT / ".venv/bin/bs"), "scan",
            "-d", domain, "--user-matrix", matrix,
            "--max", str(len(strategies)), "--parallel", "2",
            "--scan-level", "fast", "--classic",
            "--skip-deps-check", "--skip-dns-audit", "--skip-prolog",
            "--skip-ip-block", "--skip-port-block", "--skip-baseline",
            "--no-wssize", "--timeout", "4",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    os.unlink(matrix)
    return {
        "total_s": time.monotonic() - start,
        "tests": len(strategies),
        "rc": r.returncode,
        "out": r.stdout[-400:],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", default="discord.com")
    ap.add_argument("--strategies", type=int, default=len(STRATEGIES))
    ap.add_argument("--only-byedpi", action="store_true")
    args = ap.parse_args()

    strategies = STRATEGIES[: args.strategies]
    print(f"=== byedpi vs nfqws2 selection-speed bench: {args.domain} ===")
    print(f"strategies={len(strategies)}")

    b = bench_byedpi(strategies, args.domain)
    passed = sum(1 for _, ok, _ in b["results"] if ok)
    print(f"\n[byedpi]  total={b['total_s']:.2f}s tests={b['tests']} "
          f"test/sec={b['tests']/max(b['total_s'],0.001):.2f} passed={passed}")
    for s, ok, ms in b["results"]:
        tag = "PASS" if ok else "FAIL"
        print(f"  {tag:4s} {ms:6.0f}ms  {s[:50]}")

    if not args.only_byedpi:
        n = bench_nfqws2(strategies, args.domain)
        print(f"\n[nfqws2] total={n['total_s']:.2f}s tests={n['tests']} "
              f"test/sec={n['tests']/max(n['total_s'],0.001):.2f} rc={n['rc']}")
        if n["out"]:
            print(f"  tail: {n['out'].strip()[-200:]}")
        print(f"\nSpeedup: {n['total_s']/max(b['total_s'],0.001):.2f}× (nfqws2/byedpi)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
