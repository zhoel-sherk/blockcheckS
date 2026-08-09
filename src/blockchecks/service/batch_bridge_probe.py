"""Single bridge probe — publish strategy id to shm IPC and curl nfqws2."""

from __future__ import annotations

from blockchecks.checkers.curl_probe import (
    CurlProbeRequest,
    is_googlevideo_domain,
    prepare_googlevideo_probe,
    worker_wall_timeout,
)
from blockchecks.service.lua_session import BridgeSession
from blockchecks.service.probe import invoke_curl_probe_worker, probe_request_dict


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
) -> dict:
    """Publish strategy id to shm IPC and curl (nfqws2 already running)."""
    is_http = protocol == "http"
    is_gv = not is_http and is_googlevideo_domain(domain)

    if is_gv:
        probe_req, gv_err = prepare_googlevideo_probe(domain, resolved_ip=resolved_ip)
        if gv_err:
            return gv_err
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

    session.bridge.truncate_events()
    session.bridge.publish(strategy_id, gen, strategy if extra_lua_desync else None)

    probe_req.timeout = timeout
    payload = {
        "mode": "single",
        "request": probe_request_dict(probe_req),
        "repeats": max(1, int(repeats)),
        "parallel_repeats": bool(parallel_repeats and repeats > 1),
        "repeats_mode": repeats_mode,
        "quick_break": bool(quick_break),
    }
    wall = worker_wall_timeout(
        timeout,
        repeats,
        n_domains=1,
        curl_parallel=1,
        parallel_repeats=parallel_repeats,
    )
    data = invoke_curl_probe_worker(session.ns_name, python_bin, payload, wall)
    data["settle_ms"] = 0.0
    data["bridge_gen"] = gen
    data["bridge_id"] = strategy_id
    events = session.bridge.drain_events(since_gen=gen)
    data["bridge_events"] = [e.event for e in events]
    return data
