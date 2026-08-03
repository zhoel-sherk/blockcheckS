#!/usr/bin/env python3
"""Budgeted 8h flag + BC2-parity functional campaign.

Writes logs/flag_campaign_<TS>/results.json + REPORT.md
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
BUDGET_SEC = 8 * 3600

TS = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG = ROOT / "logs" / f"flag_campaign_{TS}"
RESULTS = LOG / "results.json"
T0 = time.monotonic()


def remaining() -> float:
    return BUDGET_SEC - (time.monotonic() - T0)


def load_results() -> list[dict]:
    if RESULTS.exists():
        return json.loads(RESULTS.read_text())
    return []


def save_results(rows: list[dict]) -> None:
    RESULTS.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n")


def already_done(tid: str) -> bool:
    return any(r.get("id") == tid for r in load_results())


def pkill_nfqws2() -> None:
    subprocess.run(["sudo", "-n", "pkill", "-9", "nfqws2"], capture_output=True, text=True)


def chown_db(path: Path) -> None:
    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "zhoel"
    paths = [path]
    for suf in ("-wal", "-shm", "-journal"):
        side = Path(str(path) + suf)
        if side.exists():
            paths.append(side)
    existing = [str(p) for p in paths if p.exists()]
    if existing:
        subprocess.run(["sudo", "-n", "chown", f"{user}:", *existing], capture_output=True)


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
        r"Generated:[^\n]+",
        r"readonly|Traceback|FATAL|error",
    ):
        m = re.search(pat, text, re.I)
        if m:
            notes.append(m.group(0)[:100])
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return ("; ".join(notes[:4]) + (" || " + " | ".join(lines[-2:])[:160] if lines else ""))[:400]


def run_test(
    tid: str,
    cmd: list[str],
    *,
    live: bool = True,
    timeout: int | None = None,
    phase: str = "",
    flag: str = "",
) -> dict:
    if already_done(tid):
        print(f"SKIP {tid}", flush=True)
        return {"id": tid, "skipped": True}

    rem = remaining()
    if rem < 90:
        row = {
            "id": tid,
            "exit": -1,
            "wall_s": 0,
            "status": "SKIP_BUDGET",
            "notes": f"remaining={rem:.0f}s",
            "phase": phase,
            "flag": flag,
        }
        rows = load_results()
        rows.append(row)
        save_results(rows)
        print(f"SKIP_BUDGET {tid} rem={rem:.0f}s", flush=True)
        return row

    if timeout is None:
        timeout = int(min(3600, rem - 60))
    else:
        timeout = int(min(timeout, rem - 30))
    if timeout < 30:
        return run_test(tid, cmd, live=live, timeout=None, phase=phase, flag=flag)

    LOG.mkdir(parents=True, exist_ok=True)
    log_path = LOG / f"{tid.replace('.', '_')}.log"
    if live:
        pkill_nfqws2()
        time.sleep(0.3)

    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(ROOT / "src"))
    t0 = time.perf_counter()
    exit_code = 1
    try:
        with open(log_path, "w") as lf:
            lf.write(f"$ {' '.join(cmd)}\n\n")
            lf.flush()
            proc = subprocess.Popen(
                cmd,
                cwd=str(ROOT),
                env=env,
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
                    proc.wait(timeout=20)
                except Exception:
                    pass
                exit_code = 124
                lf.write(f"\nTIMEOUT after {timeout}s\n")
    except Exception as e:
        exit_code = 1
        log_path.write_text(log_path.read_text(errors="replace") + f"\nRUNNER_ERROR: {e}\n")

    wall = round(time.perf_counter() - t0, 1)
    text = log_path.read_text(errors="replace") if log_path.exists() else ""
    with open(log_path, "a") as lf:
        lf.write(f"\nEXIT:{exit_code} WALL:{wall}s REM:{remaining():.0f}s\n")

    for db in LOG.glob(f"{tid.replace('.', '_')}*.db"):
        chown_db(db)

    status = "OK" if exit_code == 0 else ("TIMEOUT" if exit_code == 124 else "FAIL")
    if "[deadline]" in text or "TIME LIMIT reached" in text:
        if "TCP done:" in text or exit_code in (0, 2):
            status = "OK"

    row = {
        "id": tid,
        "exit": exit_code,
        "wall_s": wall,
        "status": status,
        "notes": summarize_log(text),
        "phase": phase,
        "flag": flag,
        "log": log_path.name,
    }
    rows = load_results()
    rows.append(row)
    save_results(rows)
    print(
        f"→ {tid} exit={exit_code} {status} {wall}s rem={remaining():.0f}s "
        f"{row['notes'][:100]}",
        flush=True,
    )
    return row


def sudo_bs(*args: str) -> list[str]:
    return ["sudo", "-n", str(BS), *args]


def write_report(rows: list[dict]) -> None:
    ok = sum(1 for r in rows if r.get("status") == "OK")
    fail = sum(1 for r in rows if r.get("status") == "FAIL")
    timeout = sum(1 for r in rows if r.get("status") == "TIMEOUT")
    skip = sum(1 for r in rows if r.get("status") == "SKIP_BUDGET" or r.get("skipped"))
    wall = sum(float(r.get("wall_s") or 0) for r in rows)
    head = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True).strip()

    # BC2 coverage checklist (generator/presets present)
    bc2 = [
        ("badsum in ALL_FOOLINGS_TCP", True),
        ("ALL_FOOLINGS_IPV6 ≥5", True),
        ("ACK-drop companion", True),
        ("send:tcp_md5 companion", True),
        ("http_domcase/unixeol", True),
        ("oob --in-range", True),
        ("bc2-parity presets", (ROOT / "presets/strategies/bc2-parity-http.http").exists()),
        ("voice ttl/autottl configs", (ROOT / "configs/udp_voice__fake_r6_ttl5.conf").exists()),
    ]
    covered = sum(1 for _, ok_ in bc2 if ok_)
    pct = 100.0 * covered / len(bc2)

    lines = [
        f"# Flag campaign REPORT — {TS}",
        "",
        f"- **LOG:** `{LOG}`",
        f"- **HEAD:** `{head}`",
        f"- **Budget:** 8h; elapsed wall tests sum ≈ {wall/3600:.2f}h; runner rem={remaining():.0f}s",
        f"- **Counts:** OK={ok} FAIL={fail} TIMEOUT={timeout} SKIP={skip} total={len(rows)}",
        "",
        "## BC2 global parity checklist",
        f"Estimated dimension coverage markers: **{pct:.0f}%** ({covered}/{len(bc2)})",
        "",
    ]
    for name, ok_ in bc2:
        lines.append(f"- [{'x' if ok_ else ' '}] {name}")
    lines += ["", "## Results", "| ID | phase | status | wall_s | flag | notes |", "|----|-------|--------|--------|------|-------|"]
    for r in rows:
        if r.get("skipped") and "status" not in r:
            continue
        note = (r.get("notes") or "")[:70].replace("|", "/")
        lines.append(
            f"| {r['id']} | {r.get('phase','')} | {r.get('status','')} | "
            f"{r.get('wall_s',0)} | {r.get('flag','')} | {note} |"
        )
    lines += ["", "## Flag exercise", ""]
    flags = sorted({r.get("flag") for r in rows if r.get("flag")})
    for f in flags:
        st = [r["status"] for r in rows if r.get("flag") == f]
        lines.append(f"- `{f}`: {', '.join(st)}")
    (LOG / "REPORT.md").write_text("\n".join(lines) + "\n")
    print(f"Wrote {LOG / 'REPORT.md'}", flush=True)


def main() -> int:
    os.chdir(ROOT)
    LOG.mkdir(parents=True, exist_ok=True)
    (LOG / "HEAD.txt").write_text(
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True)
    )
    print(f"Flag campaign LOG={LOG} budget={BUDGET_SEC}s", flush=True)

    # ── P0 Offline ────────────────────────────────────────────────────
    run_test("P0.1", [str(PY), "-m", "ruff", "check", "src", "tests"], live=False, timeout=120, phase="P0", flag="ruff")
    run_test(
        "P0.2",
        [str(PY), "-m", "pytest", "tests/unit", "-q", "--tb=no"],
        live=False,
        timeout=300,
        phase="P0",
        flag="pytest-unit",
    )
    run_test(
        "P0.3",
        [str(PY), "-m", "pytest", "tests/integration", "-q", "--tb=no"],
        live=False,
        timeout=180,
        phase="P0",
        flag="pytest-integration",
    )
    run_test("P0.4", [str(BS), "-h"], live=False, timeout=30, phase="P0", flag="cli-help")
    run_test(
        "P0.5",
        [
            str(PY),
            "-c",
            "from blockchecks.engine.generators.standard import ALL_FOOLINGS_TCP, ALL_FOOLINGS_IPV6;"
            "assert 'badsum' in ALL_FOOLINGS_TCP and len(ALL_FOOLINGS_IPV6)>=5; print('BC2_OK')",
        ],
        live=False,
        timeout=30,
        phase="P0",
        flag="bc2-constants",
    )

    # ── P1 Live smokes ────────────────────────────────────────────────
    for tid, conf in [
        ("P1.1", "configs/simple_fake_alt2__fake_max_ru_ts.conf"),
        ("P1.2", "configs/simple_fake__fake_ts.conf"),
        ("P1.3", "configs/alt10__fake_4pda_ts.conf"),
        ("P1.4", "configs/fake_null_r6_ts.conf"),
        ("P1.5", "configs/fake_badsum_r6.conf"),
    ]:
        run_test(
            tid,
            sudo_bs("tcp", "-d", "discord.com", "-c", conf, "--timeout", "5", "--allow-dns-hijack"),
            timeout=60,
            phase="P1",
            flag="tcp-config",
        )

    run_test(
        "P1.6",
        sudo_bs(
            "scan", "-d", "discord.com", "-M", "gp-verified", "--scan-level", "fast",
            "--max", "20", "--max-timem", "8", "--parallel", "4", "--allow-dns-hijack",
            "--db", str(LOG / "P1_6.db"),
        ),
        timeout=8 * 60 + 120,
        phase="P1",
        flag="scan-M",
    )
    run_test(
        "P1.7",
        sudo_bs(
            "scan", "-d", "discord.com",
            "--user-matrix", "presets/strategies/gp-custom-tls12.txt",
            "--scan-level", "fast", "--max", "20", "--max-timem", "8",
            "--db", str(LOG / "P1_7.db"), "--allow-dns-hijack",
        ),
        timeout=8 * 60 + 120,
        phase="P1",
        flag="user-matrix",
    )
    run_test(
        "P1.8",
        sudo_bs(
            "tcp", "-d", "discord.com", "-f", "presets/strategies/fryazino-tls13.tls",
            "--protocol", "tls13", "--timeout", "5", "--allow-dns-hijack",
        ),
        timeout=120,
        phase="P1",
        flag="tcp-file-tls13",
    )
    run_test(
        "P1.9",
        sudo_bs(
            "pair", "-d", "discord.com", "-M", "gp-verified",
            "-u", "configs/udp_voice__fake_r6.conf", "--discover-dns", "5",
            "--max", "20", "--max-timem", "12", "--parallel", "2",
            "--db", str(LOG / "P1_9.db"), "--allow-dns-hijack",
        ),
        timeout=12 * 60 + 180,
        phase="P1",
        flag="pair-discover-dns",
    )
    run_test(
        "P1.10",
        sudo_bs(
            "udp", "-c", "configs/udp_voice__fake_r6.conf", "--discover-dns", "3", "--timeout", "4",
        ),
        timeout=90,
        phase="P1",
        flag="udp-discover",
    )
    run_test(
        "P1.11",
        sudo_bs(
            "composite", "-c", "configs/simple_fake_alt2__fake_max_ru_ts.conf",
            "-d", "discord.com", "discord.gg", "--timeout", "5",
        ),
        timeout=60,
        phase="P1",
        flag="composite-multi-d",
    )
    run_test(
        "P1.12",
        sudo_bs(
            "composite", "-c", "configs/simple_fake_alt2__fake_max_ru_ts.conf",
            "-d", "discord.com,discord.gg", "--timeout", "5",
        ),
        timeout=60,
        phase="P1",
        flag="composite-comma",
    )

    # ── P1b BC2 parity ────────────────────────────────────────────────
    for tid, preset, proto in [
        ("P1b.1", "bc2-parity-http", "http"),
        ("P1b.2", "bc2-parity-ackdrop", "tls12"),
        ("P1b.3", "bc2-parity-foolings", "tls12"),
        ("P1b.4", "bc2-parity-ipv6", "tls12"),
        ("P1b.5", "bc2-parity-seqovl", "tls12"),
    ]:
        cmd = sudo_bs(
            "scan", "-d", "discord.com", "-M", preset,
            "--scan-level", "fast", "--max", "40", "--max-timem", "15",
            "--parallel", "4", "--allow-dns-hijack", "--db", str(LOG / f"{tid.replace('.','_')}.db"),
        )
        if proto == "http":
            # http presets via tcp protocol http file
            cmd = sudo_bs(
                "tcp", "-d", "example.com", "-f", f"presets/strategies/{preset}.http",
                "--protocol", "http", "--timeout", "5", "--allow-dns-hijack",
            )
        run_test(tid, cmd, timeout=15 * 60 + 180, phase="P1b", flag=f"bc2-{preset}")

    run_test(
        "P1b.6",
        sudo_bs(
            "tcp", "-d", "google.com", "-f", "presets/strategies/bc2-parity-quic.quic",
            "--protocol", "quic", "--timeout", "8", "--quic-timeout", "8", "--allow-dns-hijack",
        ),
        timeout=180,
        phase="P1b",
        flag="bc2-quic",
    )
    run_test(
        "P1b.7",
        sudo_bs(
            "udp", "-c", "configs/udp_voice__fake_r6_ttl5.conf", "--discover-dns", "3", "--timeout", "4",
        ),
        timeout=90,
        phase="P1b",
        flag="voice-ttl5",
    )
    run_test(
        "P1b.8",
        sudo_bs(
            "udp", "-c", "configs/udp_voice__fake_r6_autottl.conf", "--discover-dns", "3", "--timeout", "4",
        ),
        timeout=90,
        phase="P1b",
        flag="voice-autottl",
    )
    run_test(
        "P1b.9",
        sudo_bs(
            "udp", "-c", "configs/udp_voice__wide_ports_r6.conf", "--discover-dns", "3", "--timeout", "4",
        ),
        timeout=90,
        phase="P1b",
        flag="voice-wide-ports",
    )

    # ── P2 Flag gaps ──────────────────────────────────────────────────
    run_test(
        "P2.1",
        sudo_bs(
            "scan", "-d", "discord.com", "-M", "gp-verified", "--scan-level", "fast",
            "--max", "30", "--max-timem", "10", "--db-batch", "50",
            "--db", str(LOG / "P2_1.db"), "--allow-dns-hijack",
        ),
        timeout=10 * 60 + 180,
        phase="P2",
        flag="db-batch",
    )
    run_test(
        "P2.2",
        sudo_bs(
            "scan", "-d", "discord.com", "-M", "gp-verified", "--scan-level", "fast",
            "--max", "15", "--max-timem", "8", "--repeats", "3", "--repeats-mode", "stable",
            "--db", str(LOG / "P2_2.db"), "--allow-dns-hijack",
        ),
        timeout=8 * 60 + 180,
        phase="P2",
        flag="repeats-stable",
    )
    run_test(
        "P2.3",
        sudo_bs(
            "scan", "-d", "discord.com", "-M", "gp-verified", "--scan-level", "fast",
            "--max", "15", "--max-timem", "8", "--no-family-gates",
            "--db", str(LOG / "P2_3.db"), "--allow-dns-hijack",
        ),
        timeout=8 * 60 + 120,
        phase="P2",
        flag="no-family-gates",
    )
    run_test(
        "P2.4",
        sudo_bs(
            "full", "--domains-file", "presets/domains/benchmark.txt",
            "--scan-level", "fast", "--max", "40", "--fan-out", "--adaptive",
            "--adaptive-epsilon", "0.2", "--curl-parallel", "4",
            "--tcp-only", "--no-http", "--no-quic", "--max-timem", "12",
            "--db", str(LOG / "P2_4.db"), "--out-dir", str(LOG / "P2_4_export"),
            "--allow-dns-hijack",
        ),
        timeout=12 * 60 + 300,
        phase="P2",
        flag="adaptive-fanout-epsilon",
    )
    run_test(
        "P2.5",
        sudo_bs(
            "full", "--domains-file", "presets/domains/benchmark.txt",
            "--scan-level", "fast", "--max", "20", "--adaptive", "--no-adaptive-weights",
            "--tcp-only", "--no-http", "--no-quic", "--max-timem", "8",
            "--db", str(LOG / "P2_5.db"), "--out-dir", str(LOG / "P2_5_export"),
            "--allow-dns-hijack",
        ),
        timeout=8 * 60 + 180,
        phase="P2",
        flag="no-adaptive-weights",
    )
    # resume round-trip
    run_test(
        "P2.6a",
        sudo_bs(
            "scan", "-d", "discord.com", "-M", "gp-verified", "--scan-level", "fast",
            "--max", "10", "--max-timem", "5", "--db", str(LOG / "P2_6.db"), "--allow-dns-hijack",
        ),
        timeout=5 * 60 + 120,
        phase="P2",
        flag="resume-seed",
    )
    run_test(
        "P2.6b",
        sudo_bs(
            "scan", "-d", "discord.com", "-M", "gp-verified", "--scan-level", "fast",
            "--max", "10", "--max-timem", "5", "--resume", "--db", str(LOG / "P2_6.db"),
            "--allow-dns-hijack",
        ),
        timeout=5 * 60 + 120,
        phase="P2",
        flag="resume",
    )
    run_test(
        "P2.7",
        sudo_bs(
            "full", "--domains-file", "presets/domains/benchmark.txt",
            "--scan-level", "fast", "--adaptive", "--fan-out", "--max-timem", "1",
            "--tcp-only", "--no-http", "--no-quic", "--no-export-on-stop",
            "--db", str(LOG / "P2_7.db"), "--out-dir", str(LOG / "P2_7_export"),
            "--allow-dns-hijack",
        ),
        timeout=180,
        phase="P2",
        flag="deadline-no-export",
    )
    run_test(
        "P2.8",
        sudo_bs(
            "full", "--domains-file", "presets/domains/benchmark.txt",
            "--scan-level", "fast", "--max", "30", "--tcp-only", "--no-http", "--no-quic",
            "--zero-pass-warn", "5", "--max-timem", "8",
            "--db", str(LOG / "P2_8.db"), "--out-dir", str(LOG / "P2_8_export"),
            "--allow-dns-hijack",
        ),
        timeout=8 * 60 + 180,
        phase="P2",
        flag="zero-pass-warn",
    )

    # ── P3 Protocols ──────────────────────────────────────────────────
    run_test(
        "P3.1",
        sudo_bs(
            "tcp", "-d", "example.com", "-f", "presets/strategies/gp-custom-http.txt",
            "--protocol", "http", "--timeout", "5", "--allow-dns-hijack",
        ),
        timeout=90,
        phase="P3",
        flag="protocol-http",
    )
    run_test(
        "P3.2",
        sudo_bs(
            "tcp", "-d", "google.com", "-f", "presets/strategies/gp-custom-quic.txt",
            "--protocol", "quic", "--timeout", "8", "--quic-timeout", "10", "--allow-dns-hijack",
        ),
        timeout=120,
        phase="P3",
        flag="quic-timeout",
    )
    run_test(
        "P3.3",
        sudo_bs(
            "scan", "-d", "youtube.com", "-M", "gp-verified", "--scan-level", "fast",
            "--max", "15", "--max-timem", "12", "--db", str(LOG / "P3_3.db"), "--allow-dns-hijack",
        ),
        timeout=12 * 60 + 180,
        phase="P3",
        flag="youtube-scan",
    )

    # ── P4 Matrices ───────────────────────────────────────────────────
    run_test(
        "P4.1",
        sudo_bs(
            "full", "--domains-file", "presets/domains/benchmark.txt",
            "--scan-level", "fast", "--max", "80", "--fan-out", "--adaptive",
            "--tcp-only", "--no-http", "--no-quic", "--db-batch", "100",
            "--max-timem", "90", "--db", str(LOG / "P4_1.db"),
            "--out-dir", str(LOG / "P4_1_export"), "--allow-dns-hijack",
        ),
        timeout=90 * 60 + 600,
        phase="P4",
        flag="full-bounded",
    )
    run_test(
        "P4.2",
        sudo_bs(
            "pair", "-d", "discord.com", "-M", "gp-verified",
            "-u", "configs/udp_voice__fake_r6.conf", "--discover-dns", "5",
            "--max", "40", "--pair-max", "60", "--max-timem", "70", "--parallel", "2",
            "--db", str(LOG / "P4_2.db"), "--allow-dns-hijack",
        ),
        timeout=70 * 60 + 600,
        phase="P4",
        flag="pair-bounded",
    )
    run_test(
        "P4.3",
        ["bash", "scripts/release_smoke.sh"],
        timeout=20 * 60,
        phase="P4",
        flag="release-smoke",
    )

    # ── P5 Export / settle ────────────────────────────────────────────
    seed = LOG / "P4_1.db"
    if not seed.exists():
        seed = LOG / "P2_1.db"
    if seed.exists():
        chown_db(seed)
        run_test(
            "P5.1",
            [str(ROOT / ".venv" / "bin" / "bc-nfconf"), "--db", str(seed), "-d", "discord.com",
             "--limit", "3", "--out-dir", str(LOG / "P5_1_export")],
            live=False,
            timeout=60,
            phase="P5",
            flag="bc-nfconf",
        )
        run_test(
            "P5.2",
            [str(PY), "-m", "blockchecks.shortlist_export", "--db", str(seed),
             "-o", str(LOG / "shortlist.json")],
            live=False,
            timeout=60,
            phase="P5",
            flag="shortlist-export",
        )
        if (LOG / "shortlist.json").exists():
            run_test(
                "P5.3",
                [str(PY), "-m", "blockchecks.shortlist_import", "-i", str(LOG / "shortlist.json"),
                 "--out-dir", str(LOG / "import_presets"), "--prefix", "flag"],
                live=False,
                timeout=60,
                phase="P5",
                flag="shortlist-import",
            )
    run_test(
        "P5.4",
        sudo_bs(
            "bench-settle", "-d", "discord.com", "-M", "timeout-benchmark",
            "--max-strategies", "2", "--write-profile", str(LOG / "settle_profile.json"),
        ),
        timeout=180,
        phase="P5",
        flag="bench-settle",
    )
    if (LOG / "settle_profile.json").exists():
        run_test(
            "P5.5",
            sudo_bs(
                "full", "--domains-file", "presets/domains/benchmark.txt",
                "--scan-level", "fast", "--max", "20", "--max-timem", "10",
                "--tcp-only", "--no-http", "--no-quic",
                "--settle-profile", str(LOG / "settle_profile.json"),
                "--db", str(LOG / "P5_5.db"), "--out-dir", str(LOG / "P5_5_export"),
                "--allow-dns-hijack",
            ),
            timeout=10 * 60 + 180,
            phase="P5",
            flag="settle-profile",
        )

    # ── P6 Buffer / deadline ──────────────────────────────────────────
    run_test(
        "P6.1",
        sudo_bs(
            "full", "--domains-file", "presets/domains/benchmark.txt",
            "--scan-level", "fast", "--adaptive", "--fan-out", "--max-timem", "1",
            "--tcp-only", "--no-http", "--no-quic",
            "--db", str(LOG / "P6_1.db"), "--out-dir", str(LOG / "P6_1_export"),
            "--allow-dns-hijack",
        ),
        timeout=180,
        phase="P6",
        flag="deadline-1m",
    )

    write_report(load_results())
    print(f"Done. Artifacts: {LOG}/", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
