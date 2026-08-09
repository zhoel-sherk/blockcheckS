"""Subprocess entry for UDP voice probe inside netns (no sys.path hacks)."""

from __future__ import annotations

import json
import sys


def run_probe(ip: str, port: int, timeout: float, try_burst: bool = False) -> dict:
    from blockchecks.checkers.udp_voice import voice_udp_probe

    ok, lat, detail, method = voice_udp_probe(ip, port, timeout, try_burst=try_burst)
    return {
        "success": ok,
        "latency_ms": round(lat, 1),
        "detail": detail,
        "method": method,
        "burst": try_burst,
    }


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    try_burst = False
    if "--burst" in args:
        try_burst = True
        args = [a for a in args if a != "--burst"]
    if len(args) != 3:
        print(
            "usage: python -m blockchecks.engine._probe_worker IP PORT TIMEOUT [--burst]",
            file=sys.stderr,
        )
        return 2
    ip, port_s, timeout_s = args
    data = run_probe(ip, int(port_s), float(timeout_s), try_burst=try_burst)
    print(json.dumps(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
