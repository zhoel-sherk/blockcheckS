#!/usr/bin/env python3
"""Diagnose lua-bridge boot race behind "bridge PASS without APPLIED".

Boots a fresh BridgeSession K times; right after each boot fires P sequential
probes against a domain, recording APPLIED presence, event counts and timing.

Hypotheses tested:
  A. settle waits only for process visibility (/proc), so early probes leave
     the netns while nfqws2 has not bound NFQUEUE yet (--queue-bypass lets
     traffic through untouched -> PASS with zero events).
  B. new daemon dies on queue-bind conflict -> whole batch runs clean.

Baseline phase probes the domain WITHOUT nfqws2/NFQUEUE to establish whether
the target is reachable with no desync at all (false-PASS candidate).

Usage:
  sudo -E .venv/bin/python dev/diag_bridge_boot.py \
      [--boots 8] [--probes 6] [--boot-delay-ms 0] \
      [--domain discordcdn.com] [--timeout 3]

Read-only wrt state.db: nothing is persisted to the campaign DB.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from blockchecks.checkers.curl_probe import (  # noqa: E402
    CurlProbeRequest,
    worker_wall_timeout,
)
from blockchecks.service.lua_bridge_ipc import LuaBridge  # noqa: E402
from blockchecks.service.lua_session import BridgeSession  # noqa: E402
from blockchecks.service.probe import invoke_curl_probe_worker, probe_request_dict  # noqa: E402

DEFAULT_STRATEGY = "fake:blob=stun:repeats=6:tcp_ts=-1000"


def probe_once_clean(ns_name: str, python_bin: str, domain: str, timeout: float) -> dict:
    """Curl probe in netns WITHOUT any nfqws2/NFQUEUE (baseline reachability)."""
    req = CurlProbeRequest(domain=domain, timeout=timeout, resolve_name=domain.split("/")[0])
    payload = {
        "mode": "single",
        "request": probe_request_dict(req),
        "repeats": 1,
        "parallel_repeats": False,
        "repeats_mode": "fast",
        "quick_break": False,
    }
    wall = worker_wall_timeout(timeout, 1)
    return invoke_curl_probe_worker(ns_name, python_bin, payload, wall)


def probe_via_bridge(
    session: BridgeSession,
    sid: int,
    gen: int,
    strategy: str,
    domain: str,
    timeout: float,
    python_bin: str,
    disable_ech: bool = True,
    resolved_ip: str | None = None,
) -> dict:
    from blockchecks.service.batch_bridge_probe import run_tcp_check_bridge

    return run_tcp_check_bridge(
        session,
        sid,
        gen,
        strategy,
        domain,
        timeout,
        python_bin,
        disable_ech=disable_ech,
        resolved_ip=resolved_ip,
    )


async def run(args: argparse.Namespace) -> int:
    from blockchecks.engine.config import BLOB_DIR
    from blockchecks.service.netns_pool import NetNsPool

    python_bin = sys.executable
    t_deadline = time.monotonic() + args.max_sec
    t_run0 = time.monotonic()
    blob_hint = f"blobs dir: {BLOB_DIR}"

    pool = NetNsPool(size=1, base="bs-diag")
    await asyncio.to_thread(pool.create_all)
    await pool.seed()
    ns = await pool.acquire()
    print(
        f"[+{time.monotonic() - t_run0:6.1f}s] netns: {ns}  {blob_hint}",
        flush=True,
    )

    # --- Baseline: no nfqws2, no NFQUEUE rule --------------------------------
    base = probe_once_clean(ns, python_bin, args.domain, args.timeout)
    print(
        f"\n[baseline] no-nfqws2 probe {args.domain}: "
        f"success={base.get('success')} http={base.get('http_code')} "
        f"latency={base.get('latency_ms')}ms err={base.get('error', '')[:80]}",
        flush=True,
    )

    session = BridgeSession(
        ns_name=ns,
        strategies=args.strategies.split(";") if args.multi else [DEFAULT_STRATEGY],
        bridge=LuaBridge(ns),
    )
    rows: list[dict] = []
    aborted = False
    try:
        gen = 0
        for boot in range(1, args.boots + 1):
            if time.monotonic() > t_deadline:
                aborted = True
                break
            t0 = time.perf_counter()
            settle_s = session.boot()
            boot_ms = (time.perf_counter() - t0) * 1000
            if args.boot_delay_ms > 0:
                await asyncio.sleep(args.boot_delay_ms / 1000.0)
            delay_note = f" delay={args.boot_delay_ms}ms" if args.boot_delay_ms else ""
            print(
                f"\n[+{time.monotonic() - t_run0:6.1f}s] === boot #{boot}: "
                f"settle={settle_s * 1000:.0f}ms wall={boot_ms:.0f}ms{delay_note}",
                flush=True,
            )
            for idx in range(1, args.probes + 1):
                if time.monotonic() > t_deadline:
                    aborted = True
                    break
                gen += 1
                t_start = (time.perf_counter() - t0) * 1000
                sid = idx if args.multi else 1
                strat_line = (
                    session.strategies[(idx - 1) % len(session.strategies)]
                    if args.multi
                    else DEFAULT_STRATEGY
                )
                data = probe_via_bridge(
                    session,
                    sid,
                    gen,
                    strat_line,
                    args.domain,
                    args.timeout,
                    python_bin,
                    resolved_ip=args.ip or None,
                )
                events = data.get("bridge_events") or []
                try:
                    raw_lines = session.bridge.paths.events.read_text(
                        encoding="utf-8"
                    ).splitlines()
                except OSError:
                    raw_lines = []
                raw_kinds: dict[str, int] = {}
                raw_gens: list[str] = []
                for ln in raw_lines:
                    if '"APPLIED"' in ln:
                        raw_kinds["APPLIED"] = raw_kinds.get("APPLIED", 0) + 1
                        g = ln.split('"gen":')[1].split(",")[0] if '"gen":' in ln else "?"
                        i = ln.split('"id":')[1].split(",")[0] if '"id":' in ln else "?"
                        raw_gens.append(f"{i}/{g}")
                    elif "STRATEGY_FAIL" in ln:
                        raw_kinds["FAIL"] = raw_kinds.get("FAIL", 0) + 1
                row = {
                    "boot": boot,
                    "idx": idx,
                    "t_start_ms": t_start,
                    "success": bool(data.get("success")),
                    "http": data.get("http_code", 0),
                    "applied": bool(data.get("bridge_applied")),
                    "events": ",".join(events) or "-",
                    "raw_applied": raw_kinds.get("APPLIED", 0),
                    "raw_fail": raw_kinds.get("FAIL", 0),
                    "raw_ids_gens": " ".join(raw_gens[:3]),
                    "err": (data.get("error") or "")[:60],
                }
                rows.append(row)
                print(
                    f"  probe[{idx}] t+{t_start:7.0f}ms -> "
                    f"success={row['success']!s:5} http={row['http']:3} "
                    f"applied={row['applied']!s:5} filt=[{row['events']}] "
                    f"raw(APPLIED={row['raw_applied']} FAIL={row['raw_fail']} "
                    f"id/gen={row['raw_ids_gens']}) "
                    f"{('ERR:' + row['err']) if row['err'] else ''}",
                    flush=True,
                )
    finally:
        session.shutdown()
        await pool.release(ns)

    # --- Summary -------------------------------------------------------------
    total = len(rows)
    if not total:
        print(f"\nno probe rows collected (aborted={aborted})", flush=True)
        return 1
    by_idx: dict[int, list[dict]] = {}
    for r in rows:
        by_idx.setdefault(r["idx"], []).append(r)
    print(
        f"\n=== summary (per probe position across boots; aborted={aborted}) ===",
        flush=True,
    )
    header = f"{'pos':>4} {'pass':>6} {'applied':>8} {'no_ev_pass':>11} {'avg_t0ms':>9}"
    print(header)
    suspicious = 0
    for idx in sorted(by_idx):
        grp = by_idx[idx]
        n_pass = sum(r["success"] for r in grp)
        n_app = sum(r["applied"] for r in grp)
        n_susp = sum(r["success"] and not r["applied"] for r in grp)
        suspicious += n_susp
        avg_t = sum(r["t_start_ms"] for r in grp) / len(grp)
        print(
            f"{idx:>4} {n_pass:>4}/{len(grp)} {n_app:>4}/{len(grp)} "
            f"{n_susp:>7}/{len(grp)} {avg_t:>9.0f}"
        )
    boots_all_dead = sum(
        1
        for b in {r["boot"] for r in rows}
        if not any(r["applied"] for r in rows if r["boot"] == b)
    )
    print(
        f"\ntotal probes={total} suspicious_passes={suspicious} "
        f"({100.0 * suspicious / total:.1f}%)  boots_without_any_applied="
        f"{boots_all_dead}/{args.boots}",
        flush=True,
    )
    print(f"baseline_no_nfqws2_pass={bool(base.get('success'))}", flush=True)
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--boots", type=int, default=6)
    ap.add_argument("--probes", type=int, default=5)
    ap.add_argument("--boot-delay-ms", type=int, default=0)
    ap.add_argument("--domain", default="discordcdn.com")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--ip", default="", help="pinned A-record (CURLOPT_RESOLVE), avoids in-netns DNS")
    ap.add_argument(
        "--multi",
        action="store_true",
        help="batch of 5 strategies, probe k uses strategy id k (production-like)",
    )
    ap.add_argument(
        "--strategies",
        default=";".join(
            [
                "fake:blob=stun:repeats=6:tcp_ts=-1000",
                "fake:blob=max_ru:repeats=6:tcp_ts=-1000",
                "multisplit:snap=3",
                "hostfakesplit:nofake2:tcp_ts=-1000",
                "fake:blob=google:repeats=4:tls_mod=rnd",
            ]
        ),
        help="';'-separated strategy lines for --multi batch",
    )
    ap.add_argument(
        "--max-sec",
        type=int,
        default=240,
        help="global deadline; loops stop between probes when exceeded",
    )
    args = ap.parse_args()
    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
