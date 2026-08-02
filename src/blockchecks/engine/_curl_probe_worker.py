"""Subprocess entry for TCP curl probes inside netns (GV-3)."""

from __future__ import annotations

import json
import sys

from blockchecks.checkers.curl_probe import (
    CurlProbeBatch,
    CurlProbeRequest,
    run_curl_probe_batch,
    run_curl_probe_with_repeats,
)


def _request_from_dict(data: dict) -> CurlProbeRequest:
    return CurlProbeRequest(
        domain=data["domain"],
        timeout=float(data.get("timeout", 5.0)),
        resolved_ip=data.get("resolved_ip"),
        resolve_name=data.get("resolve_name"),
        curl_url=data.get("curl_url"),
        disable_ech=bool(data.get("disable_ech", False)),
        googlevideo=bool(data.get("googlevideo", False)),
        protocol=data.get("protocol", "tls12"),
    )


def run_payload(payload: dict) -> dict:
    mode = payload.get("mode", "single")
    if mode == "batch":
        batch = CurlProbeBatch(
            requests=[_request_from_dict(r) for r in payload.get("requests", [])],
            curl_parallel=int(payload.get("curl_parallel", 4)),
            repeats=int(payload.get("repeats", 1)),
            parallel_repeats=bool(payload.get("parallel_repeats", False)),
            repeats_mode=str(payload.get("repeats_mode", "fast")),
            quick_break=bool(payload.get("quick_break", False)),
        )
        return run_curl_probe_batch(batch)

    req = _request_from_dict(payload["request"])
    repeats = int(payload.get("repeats", 1))
    parallel = bool(payload.get("parallel_repeats", False))
    return run_curl_probe_with_repeats(
        req,
        repeats=repeats,
        parallel_repeats=parallel,
        repeats_mode=str(payload.get("repeats_mode", "fast")),
        quick_break=bool(payload.get("quick_break", False)),
    )


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
