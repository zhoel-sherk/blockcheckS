#!/usr/bin/env python3
"""Harvest live rr*---sn-*.googlevideo.com hosts via yt-dlp → real-пул GGC.

Реальные ссылки живут ≤6ч — TTL пула такой же. Запускать ИЗНУТРИ обхода
(иначе yt-dlp не достанет YouTube): например через netns с рабочей стратегией,
либо с прокси (env HTTPS_PROXY). Результат: CACHE/ggc_real_hosts.json.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

RR = re.compile(r"https?://(rr\d+---sn-[a-z0-9-]+\.googlevideo\.com)/", re.I)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--video", default="https://www.youtube.com/watch?v=jNQXAC9IVRw",
                    help="любой публичный ролик (по умолчанию 'Me at the zoo')")
    ap.add_argument("--out", default="")
    ap.add_argument("--format", default="worst[ext=mp4]/worst", help="лёгкий формат")
    args = ap.parse_args()

    ytdlp = Path(__file__).resolve().parents[1] / ".venv/bin/yt-dlp"
    cmd = [str(ytdlp), "-f", args.format, "--get-url", "--no-warnings", args.video]
    print("running:", " ".join(cmd[:6]), "...")
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    hosts = sorted({m.group(1) for m in RR.finditer(out.stdout)})
    if not hosts:
        print("ERROR: ни одного googlevideo хоста не найдено", file=sys.stderr)
        print(out.stderr[-500:], file=sys.stderr)
        return 1
    dest = Path(args.out) if args.out else None
    if dest is None:
        from blockchecks.engine.ggc_pool import real_pool_path
        dest = real_pool_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps({"timestamp": time.time(), "hosts": hosts},
                               indent=1), encoding="utf-8")
    print(f"OK: {len(hosts)} живых узлов → {dest}")
    for h in hosts[:10]:
        print(" ", h)
    return 0


if __name__ == "__main__":
    sys.exit(main())
