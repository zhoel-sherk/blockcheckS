"""One lua-bridge probe: publish strategy id on shm IPC and curl through nfqws2."""

from __future__ import annotations

import time

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


def _drain_with_poll(bridge, since_gen: int, expect_id: int) -> list:
    """Drain bridge events with a short retry: Lua may flush its APPLIED line
    a few ms after curl returns (write latency under load). Without the poll
    such probes were misread as "daemon dead" and triggered costly reboots."""
    events = bridge.drain_events(since_gen=since_gen, expect_id=expect_id)
    if events:
        return events
    for _ in range(5):
        time.sleep(0.04)
        events = bridge.drain_events(since_gen=since_gen, expect_id=expect_id)
        if events:
            break
    return events


def _attach_bridge_verdict(data: dict, events: list, session=None) -> None:
    """Attach APPLIED / rst-in provenance for this probe.

    ``bridge_applied`` is True only when an APPLIED event actually executed
    at least one instance (matched != 0). Stale-gen events for our own
    strategy id are rescued inside drain_events(expect_id=...).
    """
    data["bridge_applied"] = any(e.is_applied() for e in events)
    if not data["bridge_applied"] and session is not None:
        # Diagnostic context for the "PASS without APPLIED" warning: raw
        # events as Lua wrote them (pre-drain-filter), so lost-vs-filtered
        # is distinguishable post-mortem.
        try:
            raw = session.bridge.paths.events.read_text(encoding="utf-8")
            raw_lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        except Exception:
            raw_lines = []
        data["bridge_raw_tail"] = " ; ".join(ln[-90:] for ln in raw_lines[-2:])
    _attach_rst_in(data, events)


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
        events = _drain_with_poll(session.bridge, gen, strategy_id)
        data["bridge_events"] = [e.event for e in events]
        _attach_bridge_verdict(data, events, session)
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
    events = _drain_with_poll(session.bridge, gen, strategy_id)
    data["bridge_events"] = [e.event for e in events]
    _attach_bridge_verdict(data, events, session)
    return data


def _run_quic_bridge_probe(
    ns_name: str,
    python_bin: str,
    domain: str,
    timeout: float,
    resolved_ip: str | None,
) -> dict:
    """HTTP/3 (QUIC) probe via check_http3 in the netns subprocess."""
    from blockchecks.checkers.http3 import quic_subprocess_result

    return quic_subprocess_result(ns_name, python_bin, domain, timeout, resolved_ip)
