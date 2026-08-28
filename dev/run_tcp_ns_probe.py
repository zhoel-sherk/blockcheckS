#!/usr/bin/env python3
"""Acquire one NetNsPool slot and run ``bs tcp --ns`` (functional smoke)."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BS = os.environ.get("BS", str(ROOT / ".venv" / "bin" / "bs"))
STRAT = "fake:blob=stun:repeats=6:tcp_ts=-1000"


async def _run(domain: str) -> int:
    from blockchecks.service.netns_pool import NetNsPool

    pool = NetNsPool(size=1, base="bs-smk")
    pool.create_all()
    await pool.seed()
    ns = await pool.acquire()
    try:
        proc = subprocess.run(
            [
                "sudo",
                "-n",
                BS,
                "tcp",
                "-d",
                domain,
                "-s",
                STRAT,
                "--ns",
                ns,
                "--timeout",
                "8",
                "--skip-deps-check",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        sys.stdout.write(proc.stdout or "")
        sys.stderr.write(proc.stderr or "")
        return proc.returncode
    finally:
        await pool.release(ns)
        pool.destroy_all()


def main() -> int:
    domain = sys.argv[1] if len(sys.argv) > 1 else "discord.com"
    return asyncio.run(_run(domain))


if __name__ == "__main__":
    raise SystemExit(main())
