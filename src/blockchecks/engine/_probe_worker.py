"""Subprocess entry for UDP voice probes inside a netns. Forwards to in_ns_workers."""

from __future__ import annotations

import json
import sys

from blockchecks.service.in_ns_workers import run_udp_worker_probe as run_probe


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
