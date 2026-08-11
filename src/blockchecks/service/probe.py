"""Public curl probe worker API (netns subprocess).

GV-3: curl_cffi runs in an isolated Python subprocess via
``blockchecks.engine._curl_probe_worker`` — never inline ``options=``.
"""

from __future__ import annotations

import json
import subprocess as sp

from blockchecks.checkers.curl_probe import CurlProbeRequest


def probe_request_dict(req: CurlProbeRequest) -> dict:
    """Serialize a CurlProbeRequest for the worker stdin JSON payload."""
    return {
        "domain": req.domain,
        "timeout": req.timeout,
        "resolved_ip": req.resolved_ip,
        "resolve_name": req.resolve_name,
        "curl_url": req.curl_url,
        "disable_ech": req.disable_ech,
        "googlevideo": req.googlevideo,
        "ggc": req.ggc,
        "ytcdn": req.ytcdn,
        "ytcdn_proxy": req.ytcdn_proxy,
        "ytcdn_bare": req.ytcdn_bare,
        "protocol": req.protocol,
    }


def invoke_curl_probe_worker(ns_name: str, py: str, payload: dict, timeout: float) -> dict:
    """Run curl probe subprocess in netns; return parsed result dict.

    On malformed stdout, returns a failure-shaped dict (never raises JSONDecodeError).
    On subprocess timeout, returns a timeout-shaped failure dict (never raises
    TimeoutExpired) — a hung worker must not lose the whole batch.
    """
    try:
        r = sp.run(
            [
                "sudo",
                "ip",
                "netns",
                "exec",
                ns_name,
                py,
                "-m",
                "blockchecks.engine._curl_probe_worker",
            ],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except sp.TimeoutExpired:
        return {
            "success": False,
            "http_code": 0,
            "latency_ms": 0,
            "content_len": 0,
            "content_ok": False,
            "throttled": False,
            "read_rate_bps": 0,
            "error": f"timeout after {timeout:.0f}s",
        }
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {
            "success": False,
            "http_code": 0,
            "latency_ms": 0,
            "content_len": 0,
            "content_ok": False,
            "throttled": False,
            "read_rate_bps": 0,
            "error": f"parse: {r.stdout[:100]}",
        }
