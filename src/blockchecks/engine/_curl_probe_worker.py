"""Subprocess entry for TCP curl probes inside netns (proxy to in_ns_workers).

Kept for back-compat (``python -m blockchecks.engine._curl_probe_worker``); the
implementation now lives in ``blockchecks.engine.in_ns_workers``.
"""

from __future__ import annotations

import json
import sys

from blockchecks.engine.in_ns_workers import run_curl_worker_payload as run_payload


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    raw = sys.stdin.read() if not args else args[0]
    if not raw:
        print(
            "usage: echo JSON | python -m blockchecks.engine._curl_probe_worker",
            file=sys.stderr,
        )
        return 2
    payload = json.loads(raw)
    print(json.dumps(run_payload(payload)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
