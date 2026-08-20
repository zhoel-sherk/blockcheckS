"""Public curl probe worker API (netns subprocess).

GV-3: curl_cffi runs in an isolated Python subprocess via
``blockchecks.engine.in_ns_workers --mode curl`` — never inline ``options=``.
"""

from __future__ import annotations

import json
import os
import signal
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


_FAIL = {
    "success": False,
    "http_code": 0,
    "latency_ms": 0,
    "content_len": 0,
    "content_ok": False,
    "throttled": False,
    "read_rate_bps": 0,
}


def _loads_probe_json(out: str | None) -> dict:
    """Parse worker JSON; tolerate leading/trailing warning text on stdout."""
    text = (out or "").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            pass
    return {**_FAIL, "error": f"parse: {text[:100]}"}


def invoke_curl_probe_worker(ns_name: str, py: str, payload: dict, timeout: float) -> dict:
    """Run curl probe subprocess in netns; return parsed result dict.

    On malformed stdout, returns a failure-shaped dict (never raises JSONDecodeError).
    On subprocess timeout, returns a timeout-shaped failure dict (never raises
    TimeoutExpired) — a hung worker must not lose the whole batch.
    Stderr is kept separate so Python/dependency warnings cannot pollute JSON.
    """
    try:
        proc = sp.Popen(
            [
                "sudo",
                "-E",
                "ip",
                "netns",
                "exec",
                ns_name,
                py,
                "-m",
                "blockchecks.engine.in_ns_workers",
                "--mode",
                "curl",
            ],
            stdin=sp.PIPE,
            stdout=sp.PIPE,
            stderr=sp.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            out, _err = proc.communicate(input=json.dumps(payload), timeout=timeout)
        except sp.TimeoutExpired:
            # killpg the whole tree: subprocess timeout only kills sudo; the
            # netns child (python worker + curl) would otherwise leak and block
            # the namespace for later batches.
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            try:
                proc.wait(timeout=5)
            except sp.TimeoutExpired:
                # The process tree is stuck in an uninterruptible state (D) —
                # SIGKILL cannot reap it. Do NOT block on it further; return a
                # timeout result and let the caller's teardown deal with the
                # hung netns (the daemon will be pkilled/destroyed separately).
                pass
            return {**_FAIL, "error": f"timeout after {timeout:.0f}s"}
    except Exception as e:
        return {**_FAIL, "error": str(e)[:120]}
    return _loads_probe_json(out)
