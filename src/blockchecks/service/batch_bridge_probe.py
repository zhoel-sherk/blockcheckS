"""One lua-bridge probe: publish strategy id on shm IPC and curl through nfqws2."""

from __future__ import annotations

from blockchecks.checkers.curl_probe import (
    CurlProbeRequest,
    is_googlevideo_domain,
    is_ytcdn_domain,
    prepare_googlevideo_probe,
    prepare_ytcdn_probe,
    worker_wall_timeout,
)
from blockchecks.service.lua_session import BridgeSession
from blockchecks.service.probe import invoke_curl_probe_worker, probe_request_dict


def _attach_rst_in(data: dict, events: list) -> None:
    """Attach DPI RST-injection details (scan_bridge STRATEGY_FAIL rst_in)."""
    rst_in = [e for e in events if e.is_rst_in()]
    data["bridge_rst_in"] = bool(rst_in)
    data["bridge_rst_in_ttl"] = max((e.ttl for e in rst_in), default=0)


def run_tcp_check_bridge(
    session: BridgeSession,
    strategy_id: int,
    gen: int,
    strategy: str,
    domain: str,
    timeout: float,
    python_bin: str,
    disable_ech: bool = False,
    resolved_ip: str | None = None,
    repeats: int = 1,
    parallel_repeats: bool = False,
    extra_lua_desync: str = "",
    protocol: str = "tls12",
    repeats_mode: str = "fast",
    quick_break: bool = False,
    resolved_ips: list[str] | None = None,
) -> dict:
    """Publish strategy id to shm IPC and curl (nfqws2 already running)."""
    is_http = protocol == "http"
    is_quic = protocol == "quic"
    is_gv = not is_http and not is_quic and is_googlevideo_domain(domain)
    is_yt = not is_http and not is_quic and is_ytcdn_domain(domain)

    session.bridge.truncate_events()
    session.bridge.publish(strategy_id, gen, strategy if extra_lua_desync else None)

    if is_quic:
        data = _run_quic_bridge_probe(session.ns_name, python_bin, domain, timeout, resolved_ip)
        data["settle_ms"] = 0.0
        data["bridge_gen"] = gen
        data["bridge_id"] = strategy_id
        events = session.bridge.drain_events(since_gen=gen)
        data["bridge_events"] = [e.event for e in events]
        data["bridge_applied"] = any(e.event == "APPLIED" for e in events)
        _attach_rst_in(data, events)
        return data

    if is_gv:
        probe_req, gv_err = prepare_googlevideo_probe(domain, resolved_ip=resolved_ip)
        if gv_err:
            return gv_err
        resolved_ip = probe_req.resolved_ip
    elif is_yt:
        probe_req, yt_err = prepare_ytcdn_probe(domain, resolved_ip=resolved_ip)
        if yt_err:
            return yt_err
        resolved_ip = probe_req.resolved_ip
    else:
        probe_req = CurlProbeRequest(
            domain=domain,
            timeout=timeout,
            resolved_ip=resolved_ip,
            resolve_name=domain.split("/")[0],
            disable_ech=disable_ech,
            protocol=protocol,
        )

    probe_req.timeout = timeout
    # Single IP: the bridge applies the strategy by domain (scan_pick via shm),
    # so the destination IP does not affect which desync is used. Retry-on-IP
    # here only multiplies the per-IP timeout on every FAIL. IP retry lives
    # in the classic path (in_ns_workers).
    ips_to_try = list(resolved_ips or [])
    if resolved_ip and resolved_ip not in ips_to_try:
        ips_to_try.insert(0, resolved_ip)
    if not ips_to_try:
        ips_to_try = [resolved_ip] if resolved_ip else [None]
    ips_to_try = ips_to_try[:1]

    data: dict = {}
    for attempt, ip in enumerate(ips_to_try):
        probe_req.resolved_ip = ip
        if attempt > 0:
            probe_req.timeout = min(timeout, 2.0)
        payload = {
            "mode": "single",
            "request": probe_request_dict(probe_req),
            "repeats": max(1, int(repeats)),
            "parallel_repeats": bool(parallel_repeats and repeats > 1),
            "repeats_mode": repeats_mode,
            "quick_break": bool(quick_break),
        }
        wall = worker_wall_timeout(
            probe_req.timeout,
            repeats,
            n_domains=1,
            curl_parallel=1,
            parallel_repeats=parallel_repeats,
        )
        data = invoke_curl_probe_worker(session.ns_name, python_bin, payload, wall)
        data["settle_ms"] = 0.0
        if ip is not None:
            data["used_ip"] = ip
        if data.get("success") or attempt == len(ips_to_try) - 1:
            break
    data["bridge_gen"] = gen
    data["bridge_id"] = strategy_id
    events = session.bridge.drain_events(since_gen=gen)
    data["bridge_events"] = [e.event for e in events]
    data["bridge_applied"] = any(e.event == "APPLIED" for e in events)
    _attach_rst_in(data, events)
    return data


def _run_quic_bridge_probe(
    ns_name: str,
    python_bin: str,
    domain: str,
    timeout: float,
    resolved_ip: str | None,
) -> dict:
    """HTTP/3 (QUIC) probe via check_http3 in the netns subprocess."""
    import json
    import subprocess as sp

    resolved_ip_lit = repr(resolved_ip) if resolved_ip else "None"
    check_code = f"""
import json
from blockchecks.checkers.http3 import check_http3
r = check_http3({domain!r}, {timeout}, pre_resolved_ip={resolved_ip_lit})
print(json.dumps({{
    "success": r.success,
    "http_code": r.http_status,
    "latency_ms": r.latency_ms,
    "content_len": r.content_length,
    "content_ok": True,
    "throttled": False,
    "read_rate_bps": 0,
    "error": r.error,
    "http_version": r.http_version,
}}))
"""
    try:
        r = sp.run(
            ["sudo", "ip", "netns", "exec", ns_name, python_bin, "-c", check_code],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        return json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        return {
            "success": False,
            "http_code": 0,
            "latency_ms": 0,
            "content_len": 0,
            "content_ok": False,
            "throttled": False,
            "read_rate_bps": 0,
            "error": f"parse: {r.stdout[:100] if 'stdout' in dir() else 'quic bridge parse'}",
        }
    except sp.TimeoutExpired:
        return {
            "success": False,
            "http_code": 0,
            "latency_ms": 0,
            "content_len": 0,
            "content_ok": False,
            "throttled": False,
            "read_rate_bps": 0,
            "error": "timeout",
        }
