#!/usr/bin/env python3
"""Focused retest of campaign FAILs after product/CLI fixes.

Writes logs/retest_<TS>/results.json + DELTA.md vs campaign baseline.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BS = ROOT / ".venv" / "bin" / "bs"
PY = ROOT / ".venv" / "bin" / "python"
BASELINE = ROOT / "logs" / "full_campaign_20260802_151123" / "results.json"

TS = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG = ROOT / "logs" / f"retest_{TS}"
RESULTS = LOG / "results.json"
MAX_SEC = 2 * 3600  # cap per live test


def load_results() -> list[dict]:
    if RESULTS.exists():
        return json.loads(RESULTS.read_text())
    return []


def save_results(rows: list[dict]) -> None:
    RESULTS.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n")


def already_done(tid: str) -> bool:
    return any(r.get("id") == tid for r in load_results())


def pkill_nfqws2() -> None:
    subprocess.run(
        ["sudo", "-n", "pkill", "-9", "nfqws2"],
        capture_output=True,
        text=True,
    )


def chown_db(path: Path) -> None:
    """Reclaim root-owned sqlite files for user-space tools."""
    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "zhoel"
    paths = [path]
    for suf in ("-wal", "-shm", "-journal"):
        side = Path(str(path) + suf)
        if side.exists():
            paths.append(side)
    subprocess.run(
        ["sudo", "-n", "chown", f"{user}:", *[str(p) for p in paths if p.exists()]],
        capture_output=True,
        text=True,
    )


def summarize_log(text: str) -> str:
    notes = []
    for pat in (
        r"(\d+)/(\d+) passed",
        r"TCP[^\n]*?(\d+)/(\d+) passed",
        r"Pairs? PASS=(\d+)/(\d+)",
        r"(\d+) PASS\b",
        r"TCP done: (\d+) PASS",
        r"TIME LIMIT reached[^\n]*",
        r"\[deadline\][^\n]*",
        r"Voice source:[^\n]+",
        r"Generated:[^\n]+",
        r"Done in \d+",
        r"error|Error|Traceback|FATAL|readonly",
    ):
        m = re.search(pat, text, re.I)
        if m:
            notes.append(m.group(0)[:120])
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    tail = " | ".join(lines[-3:])[:200]
    return ("; ".join(notes[:5]) + (" || " + tail if tail else ""))[:400]


def run_test(
    tid: str,
    cmd: list[str],
    *,
    live: bool = True,
    timeout: int = MAX_SEC,
    expect: str = "",
) -> dict:
    if already_done(tid):
        print(f"SKIP {tid} (already in results)", flush=True)
        return {"id": tid, "skipped": True}

    LOG.mkdir(parents=True, exist_ok=True)
    log_path = LOG / f"{tid.replace('.', '_')}.log"
    if live:
        pkill_nfqws2()
        time.sleep(0.5)

    full_env = os.environ.copy()
    full_env.setdefault("PYTHONPATH", str(ROOT / "src"))

    t0 = time.perf_counter()
    exit_code = 1
    try:
        with open(log_path, "w") as lf:
            lf.write(f"$ {' '.join(cmd)}\n\n")
            lf.flush()
            proc = subprocess.Popen(
                cmd,
                cwd=str(ROOT),
                env=full_env,
                stdout=lf,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            try:
                exit_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=30)
                except Exception:
                    pass
                exit_code = 124
                lf.write(f"\nTIMEOUT after {timeout}s (killed process group)\n")
                lf.flush()
    except Exception as e:
        exit_code = 1
        with open(log_path, "a") as lf:
            lf.write(f"\nRUNNER_ERROR: {e}\n")

    wall = round(time.perf_counter() - t0, 1)
    text = log_path.read_text(errors="replace") if log_path.exists() else ""
    with open(log_path, "a") as lf:
        lf.write(f"\nEXIT:{exit_code} WALL:{wall}s\n")

    # After sudo DB writes, reclaim ownership (defense in depth vs A1)
    for db in LOG.glob(f"{tid.replace('.', '_')}*.db"):
        chown_db(db)

    status = "OK" if exit_code == 0 else ("TIMEOUT" if exit_code == 124 else "FAIL")
    # Graceful time-limit stop: treat as OK even if outer kill races teardown
    if "[deadline]" in text or "TIME LIMIT reached" in text:
        if "TCP done:" in text or "Run summary:" in text or exit_code in (0, 2):
            status = "OK"

    row = {
        "id": tid,
        "exit": exit_code,
        "wall_s": wall,
        "status": status,
        "notes": summarize_log(text),
        "expect": expect,
        "log": log_path.name,
    }
    rows = load_results()
    rows.append(row)
    save_results(rows)
    print(
        f"→ {tid} exit={exit_code} wall={wall}s status={status} "
        f"notes={row['notes'][:140]}",
        flush=True,
    )
    return row


def sudo_bs(*args: str) -> list[str]:
    return ["sudo", "-n", str(BS), *args]


def write_delta(rows: list[dict]) -> None:
    baseline_rows = {}
    if BASELINE.exists():
        for r in json.loads(BASELINE.read_text()):
            baseline_rows[r["id"]] = r

    lines = [
        f"# Retest DELTA — {TS}",
        "",
        f"- **LOG:** `{LOG}`",
        f"- **Baseline:** `{BASELINE.parent.name}`",
        f"- **HEAD:** `{subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], cwd=ROOT, text=True).strip()}`",
        "",
        "| ID | baseline | retest | wall_s | notes |",
        "|----|----------|--------|--------|-------|",
    ]
    ok = fail = 0
    for r in rows:
        if r.get("skipped"):
            continue
        bid = r["id"]
        b = baseline_rows.get(bid, {})
        b_ex = b.get("exit", "?")
        b_st = "OK" if b_ex == 0 else ("TIMEOUT" if b_ex == 124 else ("INT" if b_ex == 130 else "FAIL"))
        st = r.get("status", "FAIL" if r["exit"] else "OK")
        if st == "OK":
            ok += 1
        else:
            fail += 1
        note = (r.get("notes") or "")[:80].replace("|", "/")
        lines.append(
            f"| {bid} | exit={b_ex} ({b_st}) | exit={r['exit']} ({st}) | {r['wall_s']} | {note} |"
        )
    lines += ["", f"**Retest counts:** OK={ok} FAIL={fail}", ""]
    (LOG / "DELTA.md").write_text("\n".join(lines) + "\n")
    print(f"Wrote {LOG / 'DELTA.md'}", flush=True)


def main() -> int:
    os.chdir(ROOT)
    LOG.mkdir(parents=True, exist_ok=True)
    print(f"Retest LOG={LOG}", flush=True)
    (LOG / "HEAD.txt").write_text(
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True)
    )

    # ── CLI / product fixes ───────────────────────────────────────────
    run_test(
        "P1.1",
        sudo_bs(
            "scan",
            "-d",
            "discord.com",
            "-M",
            "gp-verified",
            "--scan-level",
            "fast",
            "--parallel",
            "4",
            "--timeout",
            "5",
            "--max-timeh",
            "2",
            "--db",
            str(LOG / "P1_1.db"),
            "--allow-dns-hijack",
        ),
        expect="≥3/7 PASS",
    )

    # Fix B: no --db on bs tcp
    run_test(
        "P1.5",
        sudo_bs(
            "tcp",
            "-d",
            "discord.com",
            "-f",
            "presets/strategies/fryazino-tls13.tls",
            "--protocol",
            "tls13",
            "--timeout",
            "5",
            "--allow-dns-hijack",
        ),
        expect="CLI OK; ≥1 PASS preferred",
    )

    for tid, conf in [
        ("P1.6", "configs/simple_fake_alt2__fake_max_ru_ts.conf"),
        ("P1.8a", "configs/alt10__fake_4pda_ts.conf"),
        ("P1.8c", "configs/simple_fake_alt2__fake_max_ru_ts.conf"),
    ]:
        run_test(
            tid,
            sudo_bs(
                "tcp",
                "-d",
                "discord.com",
                "-c",
                conf,
                "--timeout",
                "5",
                "--allow-dns-hijack",
            ),
            expect="HTTP 200",
        )

    # Fix B: --user-matrix not -f
    run_test(
        "P1.9",
        sudo_bs(
            "scan",
            "-d",
            "discord.com",
            "--user-matrix",
            "presets/strategies/gp-custom-tls12.txt",
            "--scan-level",
            "fast",
            "--parallel",
            "4",
            "--max-timeh",
            "2",
            "--db",
            str(LOG / "P1_9.db"),
            "--allow-dns-hijack",
        ),
        expect="CLI OK; some PASS",
    )
    run_test(
        "P1.10",
        sudo_bs(
            "scan",
            "-d",
            "discord.com",
            "--user-matrix",
            "presets/strategies/gp-custom-dupfake.tls",
            "--scan-level",
            "fast",
            "--parallel",
            "4",
            "--max-timeh",
            "2",
            "--db",
            str(LOG / "P1_10.db"),
            "--allow-dns-hijack",
        ),
        expect="CLI OK; some PASS",
    )

    run_test(
        "P3.1",
        sudo_bs(
            "pair",
            "-d",
            "discord.com",
            "-M",
            "gp-verified",
            "-u",
            "configs/udp_voice__fake_r6.conf",
            "--discover-dns",
            "5",
            "--parallel",
            "2",
            "--timeout",
            "5",
            "--udp-timeout",
            "3",
            "--max-timeh",
            "2",
            "--db",
            str(LOG / "P3_1.db"),
            "--allow-dns-hijack",
        ),
        expect="pairs PASS≥1",
    )
    run_test(
        "P3.2",
        sudo_bs(
            "pair",
            "-d",
            "discord.com",
            "-M",
            "gp-verified",
            "-u",
            "configs/udp_voice__fake_r12.conf",
            "--discover-dns",
            "5",
            "--parallel",
            "2",
            "--timeout",
            "5",
            "--udp-timeout",
            "3",
            "--max-timeh",
            "2",
            "--db",
            str(LOG / "P3_2.db"),
            "--allow-dns-hijack",
        ),
        expect="pairs PASS≥1",
    )
    run_test(
        "P3.3",
        sudo_bs(
            "pair",
            "-d",
            "discord.com",
            "--generate",
            "--tcp-sources",
            "custom,configs",
            "--udp-sources",
            "custom,standard_udp",
            "--discover-dns",
            "5",
            "--scan-level",
            "fast",
            "--parallel",
            "2",
            "--max",
            "40",
            "--timeout",
            "5",
            "--udp-timeout",
            "3",
            "--max-timeh",
            "2",
            "--db",
            str(LOG / "P3_3.db"),
            "--allow-dns-hijack",
        ),
        expect="UDP>0; ≥1 pair PASS if TCP PASS",
    )

    # P6.1 — release smoke (has post-sudo chown)
    run_test(
        "P6.1",
        ["bash", "scripts/release_smoke.sh"],
        live=True,
        timeout=MAX_SEC,
        expect="TCP PASS + shortlist round-trip without readonly",
    )

    # P6.2 smoke — deadline proof (1 min, outer timeout 180s)
    run_test(
        "P6.2",
        sudo_bs(
            "full",
            "--fan-out",
            "--adaptive",
            "--allow-dns-hijack",
            "--domains-file",
            "presets/domains/benchmark.txt",
            "--scan-level",
            "fast",
            "--parallel",
            "4",
            "--max-timem",
            "1",
            "--tcp-only",
            "--no-http",
            "--no-quic",
            "--db",
            str(LOG / "P6_2.db"),
            "--out-dir",
            str(LOG / "P6_2_export"),
        ),
        timeout=180,
        expect="graceful stop ≤~90s; TIME LIMIT / deadline fired",
    )

    # Outer timeout = budget + 10m so graceful export is not SIGKILL'd
    run_test(
        "P6.4",
        sudo_bs(
            "full",
            "--domains-file",
            "presets/domains/coverage.txt",
            "--allow-unsafe-domains",
            "--scan-level",
            "fast",
            "--max-timeh",
            "2",
            "--tcp-only",
            "--no-http",
            "--no-quic",
            "--parallel",
            "4",
            "--allow-dns-hijack",
            "--db",
            str(LOG / "P6_4.db"),
            "--out-dir",
            str(LOG / "P6_4_export"),
        ),
        timeout=2 * 3600 + 600,
        expect="graceful stop or partial PASS, not INT",
    )

    # Fix A2: two argv domains (also works as comma after normalize)
    run_test(
        "P8.1",
        sudo_bs(
            "composite",
            "-c",
            "configs/simple_fake_alt2__fake_max_ru_ts.conf",
            "-d",
            "discord.com",
            "discord.gg",
            "--timeout",
            "5",
        ),
        expect="≥1 PASS",
    )
    # Also prove comma-token path
    run_test(
        "P8.1b",
        sudo_bs(
            "composite",
            "-c",
            "configs/simple_fake_alt2__fake_max_ru_ts.conf",
            "-d",
            "discord.com,discord.gg",
            "--timeout",
            "5",
        ),
        expect="comma split ≥1 PASS",
    )

    # Seed a small writable DB for export tools (after A1 chown)
    seed_db = LOG / "seed_export.db"
    run_test(
        "P8_seed",
        sudo_bs(
            "scan",
            "-d",
            "discord.com",
            "-M",
            "gp-verified",
            "--scan-level",
            "single",
            "--parallel",
            "2",
            "--max",
            "5",
            "--timeout",
            "5",
            "--max-timem",
            "5",
            "--db",
            str(seed_db),
            "--allow-dns-hijack",
        ),
        expect="seed DB with PASS rows",
    )
    chown_db(seed_db)

    run_test(
        "P8.3",
        [
            str(ROOT / ".venv" / "bin" / "bc-nfconf"),
            "--db",
            str(seed_db),
            "-d",
            "discord.com",
            "--limit",
            "3",
            "--out-dir",
            str(LOG / "P8_3_export"),
        ],
        live=False,
        expect="no readonly error",
    )
    run_test(
        "P8.4",
        [
            str(PY),
            "-m",
            "blockchecks.shortlist_export",
            "--db",
            str(seed_db),
            "-o",
            str(LOG / "shortlist.json"),
        ],
        live=False,
        expect="shortlist written",
    )
    run_test(
        "P8.5",
        [
            str(PY),
            "-m",
            "blockchecks.shortlist_import",
            "-i",
            str(LOG / "shortlist.json"),
            "--out-dir",
            str(LOG / "import_presets"),
            "--prefix",
            "retest",
        ],
        live=False,
        expect="import OK",
    )

    write_delta(load_results())
    print(f"Done. Artifacts: {LOG}/", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
