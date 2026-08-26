"""Start nfqws2 in a netns, run curl/STUN/HTTP3, return a result dict.
Called from AsyncTestRunner via asyncio.to_thread, or as python -m ... --mode curl|udp.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess as sp
import sys
import tempfile
from pathlib import Path

from blockchecks.checkers.curl_probe import (
    CurlProbeRequest,
    is_googlevideo_domain,
    is_ytcdn_domain,
    prepare_googlevideo_probe,
    prepare_ytcdn_probe,
    worker_wall_timeout,
    ytcdn_probe_variants,
)
from blockchecks.engine.config import RETRY_IP_TIMEOUT

log = logging.getLogger(__name__)


def udp_filter_covers_port(spec: str, port: int) -> bool:
    """True if a nfqws2 --filter-udp value includes ``port``."""
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    bounds = [
        (p.partition("-")[0], p.partition("-")[2] or p) if "-" in p else (p, p) for p in parts
    ]
    return any(a.isdigit() and b.isdigit() and int(a) <= port <= int(b) for a, b in bounds)


def voice_udp_filter_for_port(port: int) -> str:
    """VOICE_UDP_FILTER, plus the probe port if it lies outside that range."""
    from blockchecks.engine.config import VOICE_UDP_FILTER

    base = VOICE_UDP_FILTER
    return base if udp_filter_covers_port(base, port) else f"{base},{port}"


def ensure_udp_filter_lines(lines: list[str], port: int) -> list[str]:
    """Guarantee a --filter-udp that covers the probe port."""
    specs = [ln.split("=", 1)[1] for ln in lines if ln.startswith("--filter-udp=") and "=" in ln]
    if any(udp_filter_covers_port(s, port) for s in specs):
        return lines
    insert_at = next((i + 1 for i, ln in enumerate(lines) if ln.startswith("--qnum=")), 1)
    insert_at = min(insert_at, len(lines))
    return [
        *lines[:insert_at],
        f"--filter-udp={voice_udp_filter_for_port(port)}",
        *lines[insert_at:],
    ]


def _udp_base_lines() -> list[str]:
    from blockchecks.engine.config import NFQUEUE_UDP, get_lua_init_scripts

    return [
        f"--qnum={NFQUEUE_UDP}",
        "--filter-l3=ipv4",
        "--ipcache-lifetime=0",
        "--bind-fix4",
        *(f"--lua-init=@{lua}" for lua in get_lua_init_scripts() if os.path.exists(lua)),
    ]


def _strategy_cli_tokens(strategy: str) -> list[str]:
    from blockchecks.engine.conf_builder import split_cli_args

    stripped = [raw.strip() for raw in strategy.split("\n") if raw.strip()]
    return [
        tok
        for line in stripped
        for tok in (split_cli_args(line) if line.startswith("--") else [f"--lua-desync={line}"])
    ]


def _write_udp_conf(lines: list[str]) -> str:
    fd, path = tempfile.mkstemp(prefix="bs_async_udp_", suffix=".conf")
    os.close(fd)
    Path(path).write_text("\n".join(lines) + "\n")
    return path


def _load_conf_lines(path: str) -> list[str]:
    return [ln.strip() for ln in Path(path).read_text().splitlines() if ln.strip()]


def _attach_udp_queue(ns_name: str, port: int, *, coexist: bool) -> None:
    """NFQUEUE UDP to q201 after nfqws2 is up. No --queue-bypass (would skip desync)."""
    from blockchecks.engine.config import NFQUEUE_UDP
    from blockchecks.service.ns_firewall import get_ns_firewall

    fw = get_ns_firewall(ns_name)
    if not coexist:
        fw.detach()
    fw.attach(proto="udp", port=str(port), queue=NFQUEUE_UDP, bypass=False)


def _conf_from_file(strategy: str, port: int) -> str:
    src = os.path.abspath(strategy) if not os.path.isabs(strategy) else strategy
    fd, tmp_conf = tempfile.mkstemp(prefix="bs_async_udp_", suffix=".conf")
    os.close(fd)
    shutil.copy2(src, tmp_conf)
    Path(tmp_conf).write_text(
        "\n".join(ensure_udp_filter_lines(_load_conf_lines(tmp_conf), port)) + "\n"
    )
    return tmp_conf


def _inline_udp_lines(strategy: str, port: int) -> list[str]:
    from blockchecks.engine.conf_builder import add_blobs_from_strategy
    from blockchecks.engine.config import BLOB_DIR

    base = _udp_base_lines()
    lines = [base[0], f"--filter-udp={voice_udp_filter_for_port(port)}", *base[1:]]
    strategy = add_blobs_from_strategy(lines, strategy)
    if not any(ln.startswith("--blob=") for ln in lines):
        blob = os.path.join(BLOB_DIR, "discord_udp.bin")
        if os.path.exists(blob):
            lines.append(f"--blob=discord_udp:@{blob}")
    return ensure_udp_filter_lines([*lines, *_strategy_cli_tokens(strategy)], port)


def _materialize_udp_conf(strategy: str, port: int, *, is_config: bool) -> str:
    kind = "config" if is_config else ("cli" if strategy.strip().startswith("--") else "inline")
    builders = {
        "config": lambda: _conf_from_file(strategy, port),
        "cli": lambda: _write_udp_conf(
            ensure_udp_filter_lines([*_udp_base_lines(), *_strategy_cli_tokens(strategy)], port)
        ),
        "inline": lambda: _write_udp_conf(_inline_udp_lines(strategy, port)),
    }
    return builders[kind]()


def _run_quic_check(
    ns_name: str,
    strategy: str,
    domain: str,
    timeout: float,
    is_config: bool = False,
    python_bin: str = None,
    resolved_ip: str | None = None,
) -> dict:
    """Start nfqws2 QUIC desync in ns, probe domain via HTTP/3 HEAD."""
    from blockchecks.checkers.http3 import quic_subprocess_result
    from blockchecks.engine.config import NFQUEUE_UDP, PYTHON_BIN
    from blockchecks.engine.nfqws_config import _build_quic_nfqws_lines
    from blockchecks.service.nfqws2 import start_daemon as nfqws2_daemon
    from blockchecks.service.ns_firewall import get_ns_firewall

    py = python_bin or PYTHON_BIN
    tmp_conf = None

    if is_config:
        import shutil
        import tempfile as _tf

        src = os.path.abspath(strategy) if not os.path.isabs(strategy) else strategy
        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_quic_", suffix=".conf")
        os.close(_tf_fd)
        shutil.copy2(src, tmp_conf)
        nfqws2_daemon(ns_name, tmp_conf)
    else:
        import tempfile as _tf

        config_lines = _build_quic_nfqws_lines(strategy)
        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_quic_", suffix=".conf")
        os.close(_tf_fd)
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        nfqws2_daemon(ns_name, tmp_conf)

    fw = get_ns_firewall(ns_name)
    fw.attach(proto="udp", port="443", queue=NFQUEUE_UDP, bypass=True)

    try:
        return quic_subprocess_result(ns_name, py, domain, timeout, resolved_ip)
    finally:
        fw.detach_one(proto="udp", port="443", queue=NFQUEUE_UDP, bypass=True)
        if tmp_conf:
            try:
                os.unlink(tmp_conf)
            except OSError:
                pass


def _is_quic_dropped(error: str) -> bool:
    """True if a QUIC probe failed by full drop (TSPU), vs reached-CDN errors.

    A dropped session times out; an error like ``ngtcp2_conn_writev_*`` or
    ``SSL: no alternative certificate`` means the QUIC Initial reached the CDN
    (bypassed the TSPU SNI filter) but HTTP/3 did not complete.
    """
    low = (error or "").lower()
    return "timeout" in low or "timed out" in low


def _quic_fallback_variants(strategy: str) -> list[str]:
    """If a QUIC strategy times out, try fake then +badsum then +ip_ttl=1.

    Split/disorder (ipfrag) often drop; fake often reaches the CDN.
    Lines that already have badsum or ip_ttl are not duplicated.
    ``BLOCKCHECKS_QUIC_FALLBACK=0`` disables this.
    """
    if not strategy or strategy.strip().startswith("--"):
        return []
    if os.environ.get("BLOCKCHECKS_QUIC_FALLBACK", "").strip().lower() in (
        "0",
        "false",
        "off",
        "no",
    ):
        return []
    base = strategy.strip()
    out: list[str] = []
    for suffix in (":badsum", ":ip_ttl=1"):
        if suffix in base:
            continue
        out.append(base + suffix)
    return out


def _run_tcp_check(
    ns_name: str,
    strategy: str,
    domain: str,
    timeout: float,
    is_config: bool = False,
    python_bin: str = None,
    disable_ech: bool = False,
    resolved_ip: str | None = None,
    repeats: int = 1,
    parallel_repeats: bool = False,
    extra_lua_desync: str = "",
    protocol: str = "tls12",
    settle_max: float | None = None,
    settle_poll: float | None = None,
    repeats_mode: str = "fast",
    quick_break: bool = False,
    resolved_ips: list[str] | None = None,
) -> dict:
    """Start nfqws2 in ns, run curl_cffi check, return result dict."""
    from blockchecks.engine.config import NFQUEUE_TCP, PYTHON_BIN
    from blockchecks.engine.nfqws_config import _build_inline_nfqws_lines
    from blockchecks.service.nfqws2 import start_daemon as nfqws2_daemon
    from blockchecks.service.ns_firewall import get_ns_firewall
    from blockchecks.service.probe import invoke_curl_probe_worker, probe_request_dict

    py = python_bin or PYTHON_BIN
    is_http = protocol == "http"
    is_gv = not is_http and is_googlevideo_domain(domain)
    is_yt = not is_http and is_ytcdn_domain(domain)
    dport = "80" if is_http else "443"
    tmp_conf = None

    ytcdn_variants: list = []
    if is_gv:
        probe_req, gv_err = prepare_googlevideo_probe(domain, resolved_ip=resolved_ip)
        if gv_err:
            return gv_err
        resolved_ip = probe_req.resolved_ip
    elif is_yt:
        ytcdn_variants = ytcdn_probe_variants(domain, resolved_ip=resolved_ip)
        if not ytcdn_variants:
            return {"success": False, "error": "no ytcdn variants"}
        probe_req = ytcdn_variants[0]
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
    if is_config:
        src = os.path.abspath(strategy) if not os.path.isabs(strategy) else strategy
        # Copy user conf — inject daemon/debug without mutating the original
        import shutil
        import tempfile as _tf

        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_", suffix=".conf")
        os.close(_tf_fd)
        shutil.copy2(src, tmp_conf)
        if extra_lua_desync:
            with open(tmp_conf, "a", encoding="utf-8") as f:
                f.write(f"\n--lua-desync={extra_lua_desync}\n")
        settle_elapsed = nfqws2_daemon(
            ns_name, tmp_conf, settle_max=settle_max, settle_poll=settle_poll
        )
    else:
        config_lines = _build_inline_nfqws_lines(strategy, protocol, extra_lua_desync)
        import tempfile as _tf

        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_", suffix=".conf")
        os.close(_tf_fd)
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        settle_elapsed = nfqws2_daemon(
            ns_name, tmp_conf, settle_max=settle_max, settle_poll=settle_poll
        )

    fw = get_ns_firewall(ns_name)
    fw.attach(proto="tcp", port=dport, queue=NFQUEUE_TCP, bypass=True)

    probe_req.timeout = timeout
    # Retry-on-next-IP: when the resolved IP fails but nfqws2 is already
    # up, retry the curl worker against the next candidate with a shorter budget.
    ips_to_try = list(resolved_ips or [])
    if resolved_ip and resolved_ip not in ips_to_try:
        ips_to_try.insert(0, resolved_ip)
    if not ips_to_try:
        ips_to_try = [resolved_ip] if resolved_ip else [None]

    try:
        data: dict = {}
        used_ip: str | None = None
        # ytcdn: try each probe variant (bare → proxy → thumb) × IP candidates.
        # classic/gv: single probe_req × IP candidates.
        candidates = ytcdn_variants if is_yt else [probe_req]
        done_variant = False
        for variant in candidates:
            for attempt, ip in enumerate(ips_to_try):
                variant.resolved_ip = ip
                variant.timeout = timeout if attempt == 0 else min(timeout, RETRY_IP_TIMEOUT)
                payload = {
                    "mode": "single",
                    "request": probe_request_dict(variant),
                    "repeats": max(1, int(repeats)),
                    "parallel_repeats": bool(parallel_repeats and repeats > 1),
                    "repeats_mode": repeats_mode,
                    "quick_break": bool(quick_break),
                }
                wall = worker_wall_timeout(
                    variant.timeout,
                    repeats,
                    n_domains=1,
                    curl_parallel=1,
                    parallel_repeats=parallel_repeats,
                )
                data = invoke_curl_probe_worker(ns_name, py, payload, wall)
                data["settle_ms"] = round(settle_elapsed * 1000, 1)
                used_ip = ip
                if data.get("success"):
                    done_variant = True
                    break
            if done_variant:
                break
        if used_ip is not None:
            data["used_ip"] = used_ip
        return data
    finally:
        fw.detach_one(proto="tcp", port=dport, queue=NFQUEUE_TCP, bypass=True)
        if tmp_conf:
            try:
                os.unlink(tmp_conf)
            except OSError:
                pass


def _clone_request_with_ip(
    probe_requests: list[CurlProbeRequest], domain: str, ip: str
) -> CurlProbeRequest | None:
    """Return a copy of the CurlProbeRequest for *domain* with *ip* pinned."""
    for req in probe_requests:
        if req.domain == domain:
            import dataclasses

            return dataclasses.replace(req, resolved_ip=ip)
    return None


def _multi_probe_one(
    domain: str,
    protocol: str,
    resolved_ips: dict[str, str | None],
    *,
    disable_ech: bool,
    timeout: float,
) -> tuple[CurlProbeRequest, dict | None]:
    is_http = protocol == "http"
    ip = resolved_ips.get(domain)
    dispatch = (
        (is_googlevideo_domain, prepare_googlevideo_probe),
        (is_ytcdn_domain, prepare_ytcdn_probe),
    )
    for pred, prep in dispatch:
        if not is_http and pred(domain):
            return prep(domain, resolved_ip=ip)
    return (
        CurlProbeRequest(
            domain=domain,
            timeout=timeout,
            resolved_ip=ip,
            resolve_name=domain.split("/")[0],
            disable_ech=disable_ech,
            protocol=protocol,
        ),
        None,
    )


def _multi_probe_requests(
    domains: list[str],
    protocol: str,
    resolved_ips: dict[str, str | None],
    *,
    disable_ech: bool,
    timeout: float,
) -> tuple[list[CurlProbeRequest], dict[str, dict], dict[str, str | None]]:
    built = [
        _multi_probe_one(d, protocol, resolved_ips, disable_ech=disable_ech, timeout=timeout)
        for d in domains
    ]
    gv_fail = {d: err for d, (_req, err) in zip(domains, built, strict=True) if err}
    probe_requests = [req for req, err in built if not err]
    ips = dict(resolved_ips)
    for req in probe_requests:
        if req.resolved_ip:
            ips[req.domain] = req.resolved_ip
    return probe_requests, gv_fail, ips


def _run_tcp_check_multi(
    ns_name: str,
    strategy: str,
    domains: list[str],
    timeout: float,
    *,
    is_config: bool = False,
    python_bin: str | None = None,
    disable_ech: bool = False,
    resolved_ips: dict[str, str | None] | None = None,
    resolved_ip_lists: dict[str, list[str]] | None = None,
    repeats: int = 1,
    extra_lua_desync: str = "",
    protocol: str = "tls12",
    curl_parallel: int = 4,
    settle_max: float | None = None,
    settle_poll: float | None = None,
    parallel_repeats: bool = False,
    repeats_mode: str = "fast",
    quick_break: bool = False,
) -> dict[str, dict]:
    """One nfqws2 session, parallel curl across domains (B2)."""
    from blockchecks.engine.config import NFQUEUE_TCP, PYTHON_BIN
    from blockchecks.engine.nfqws_config import _build_inline_nfqws_lines
    from blockchecks.service.nfqws2 import start_daemon as nfqws2_daemon
    from blockchecks.service.ns_firewall import get_ns_firewall
    from blockchecks.service.probe import invoke_curl_probe_worker, probe_request_dict

    if not domains:
        return {}
    py = python_bin or PYTHON_BIN
    is_http = protocol == "http"
    dport = "80" if is_http else "443"
    tmp_conf = None
    resolved_ips = dict(resolved_ips or {})
    probe_requests, gv_fail, resolved_ips = _multi_probe_requests(
        domains,
        protocol,
        resolved_ips,
        disable_ech=disable_ech,
        timeout=timeout,
    )

    domains_active = [r.domain for r in probe_requests]
    if not domains_active:
        return gv_fail

    if is_config:
        import shutil
        import tempfile as _tf

        src = os.path.abspath(strategy) if not os.path.isabs(strategy) else strategy
        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_multi_", suffix=".conf")
        os.close(_tf_fd)
        shutil.copy2(src, tmp_conf)
        if extra_lua_desync:
            with open(tmp_conf, "a", encoding="utf-8") as f:
                f.write(f"\n--lua-desync={extra_lua_desync}\n")
        settle_elapsed = nfqws2_daemon(
            ns_name, tmp_conf, settle_max=settle_max, settle_poll=settle_poll
        )
    else:
        import tempfile as _tf

        config_lines = _build_inline_nfqws_lines(strategy, protocol, extra_lua_desync)
        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_multi_", suffix=".conf")
        os.close(_tf_fd)
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        settle_elapsed = nfqws2_daemon(
            ns_name, tmp_conf, settle_max=settle_max, settle_poll=settle_poll
        )

    fw = get_ns_firewall(ns_name)
    fw.attach(proto="tcp", port=dport, queue=NFQUEUE_TCP, bypass=True)

    for req in probe_requests:
        req.timeout = timeout

    payload = {
        "mode": "batch",
        "requests": [probe_request_dict(r) for r in probe_requests],
        "curl_parallel": int(curl_parallel),
        "repeats": max(1, int(repeats)),
        "parallel_repeats": bool(parallel_repeats and repeats > 1),
        "repeats_mode": repeats_mode,
        "quick_break": bool(quick_break),
    }
    try:
        wall = worker_wall_timeout(
            timeout,
            repeats,
            n_domains=len(domains_active),
            curl_parallel=int(curl_parallel),
            parallel_repeats=parallel_repeats,
        )
        raw = invoke_curl_probe_worker(ns_name, py, payload, wall)
        settle_ms = round(settle_elapsed * 1000, 1)
        out = {d: {**raw.get(d, {}), "settle_ms": settle_ms} for d in domains_active}
        # Retry-on-next-IP for failed domains: nfqws2 is already up, so
        # re-probe each failed domain against its remaining candidate IPs.
        if resolved_ip_lists:
            for d in domains_active:
                data = out.get(d)
                if data and data.get("success"):
                    continue
                remaining = [ip for ip in (resolved_ip_lists.get(d) or []) if ip]
                if not remaining:
                    continue
                for attempt, ip in enumerate(remaining):
                    req = _clone_request_with_ip(probe_requests, d, ip)
                    if req is None:
                        continue
                    req.timeout = min(timeout, RETRY_IP_TIMEOUT)
                    retry_payload = {
                        "mode": "single",
                        "request": probe_request_dict(req),
                        "repeats": max(1, int(repeats)),
                        "parallel_repeats": False,
                        "repeats_mode": repeats_mode,
                        "quick_break": bool(quick_break),
                    }
                    retry_wall = worker_wall_timeout(
                        req.timeout, repeats, n_domains=1, curl_parallel=1
                    )
                    retry = invoke_curl_probe_worker(ns_name, py, retry_payload, retry_wall)
                    retry["settle_ms"] = settle_ms
                    retry["used_ip"] = ip
                    out[d] = retry
                    if retry.get("success") or attempt == len(remaining) - 1:
                        break
        out.update(gv_fail)
        return out
    finally:
        fw.detach_one(proto="tcp", port=dport, queue=NFQUEUE_TCP, bypass=True)
        if tmp_conf:
            try:
                os.unlink(tmp_conf)
            except OSError:
                pass


def _run_udp_check(
    ns_name: str,
    strategy: str,
    ip: str,
    port: int,
    timeout: float,
    is_config: bool = False,
    python_bin: str = None,
    coexist: bool = False,
) -> dict:
    """Start nfqws2 UDP in ns, run STUN probe, return result.

    coexist=True: do not pkill existing nfqws2 (keep TCP desync for pairs);
    wait until two nfqws2 processes are visible (q200+q201) before probing.
    iptables is attached after settle, without --queue-bypass.
    """
    from blockchecks.engine.config import NFQUEUE_UDP, PYTHON_BIN
    from blockchecks.service.nfqws2 import start_daemon as nfqws2_daemon
    from blockchecks.service.ns_firewall import get_ns_firewall

    py = python_bin or PYTHON_BIN
    tmp_conf = _materialize_udp_conf(strategy, port, is_config=is_config)
    fw = get_ns_firewall(ns_name)
    try:
        nfqws2_daemon(
            ns_name,
            tmp_conf,
            kill_existing=not coexist,
            min_procs=2 if coexist else 1,
        )
        _attach_udp_queue(ns_name, port, coexist=coexist)

        probe_code = f"""
import json, os
from blockchecks.checkers.udp_voice import voice_udp_probe
_burst = os.environ.get("BLOCKCHECKS_VOICE_BURST", "").strip().lower() in ("1","true","on","yes")
ok, lat, detail, method = voice_udp_probe({ip!r}, {port}, {timeout}, try_burst=_burst)
print(json.dumps({{"success": ok, "latency_ms": lat,
    "detail": detail, "method": method}}))
"""
        burst = os.environ.get("BLOCKCHECKS_VOICE_BURST", "").strip().lower() in (
            "1",
            "true",
            "on",
            "yes",
        )
        try:
            r = sp.run(
                ["sudo", "ip", "netns", "exec", ns_name, py, "-c", probe_code],
                capture_output=True,
                text=True,
                timeout=timeout * (3 if burst else 2) + 3,
            )
            try:
                return json.loads(r.stdout)
            except json.JSONDecodeError:
                return {"success": False, "latency_ms": 0, "detail": "parse error"}
        except sp.TimeoutExpired:
            return {
                "success": False,
                "latency_ms": 0,
                "detail": "TimeoutExpired: probe subprocess timeout",
            }
    finally:
        fw.detach_one(proto="udp", port=str(port), queue=NFQUEUE_UDP, bypass=False)
        try:
            os.unlink(tmp_conf)
        except OSError:
            pass


# AsyncTestRunner


async def _save_pass_strategy_data_block(
    strategy: str,
    domain: str,
    *,
    protocol: str,
    latency_ms: float,
    http_code: int,
) -> None:
    """Persist a PASS strategy into data_block strategies.db (best-effort)."""
    try:
        from blockchecks.data_block.provider import get_provider_dir
        from blockchecks.data_block.store import ProviderStore

        store = ProviderStore(get_provider_dir())
        await store.upsert_pass_strategy(
            strategy,
            domain,
            protocol=protocol,
            latency_ms=latency_ms,
            http_code=http_code,
        )
    except Exception as exc:
        log.warning("%s", f"  WARNING: PASS upsert to data_block failed ({exc})")


# Subprocess entries (integrated from _curl_probe_worker / _probe_worker)
#
# These run inside a netns as ``python -m blockchecks.engine.in_ns_workers
# --mode curl|udp`` (see service/probe.py and engine/test_runner.py). They read
# a JSON payload from stdin and write a JSON result to stdout, preserving the
# exact contract the standalone _probe_worker / _curl_probe_worker modules had.


def _curl_request_from_dict(data: dict) -> CurlProbeRequest:
    return CurlProbeRequest(
        domain=data["domain"],
        timeout=float(data.get("timeout", 5.0)),
        resolved_ip=data.get("resolved_ip"),
        resolve_name=data.get("resolve_name"),
        curl_url=data.get("curl_url"),
        disable_ech=bool(data.get("disable_ech", False)),
        googlevideo=bool(data.get("googlevideo", False)),
        ggc=bool(data.get("ggc", False)),
        ytcdn=bool(data.get("ytcdn", False)),
        ytcdn_proxy=bool(data.get("ytcdn_proxy", False)),
        ytcdn_bare=bool(data.get("ytcdn_bare", False)),
        protocol=data.get("protocol", "tls12"),
    )


def run_curl_worker_payload(payload: dict) -> dict:
    """Run a curl probe payload (single or batch) → result dict."""
    from blockchecks.checkers.curl_probe import (
        CurlProbeBatch,
        run_curl_probe_batch,
        run_curl_probe_with_repeats,
    )

    mode = payload.get("mode", "single")
    if mode == "batch":
        batch = CurlProbeBatch(
            requests=[_curl_request_from_dict(r) for r in payload.get("requests", [])],
            curl_parallel=int(payload.get("curl_parallel", 4)),
            repeats=int(payload.get("repeats", 1)),
            parallel_repeats=bool(payload.get("parallel_repeats", False)),
            repeats_mode=str(payload.get("repeats_mode", "fast")),
            quick_break=bool(payload.get("quick_break", False)),
        )
        return run_curl_probe_batch(batch)

    req = _curl_request_from_dict(payload["request"])
    repeats = int(payload.get("repeats", 1))
    parallel = bool(payload.get("parallel_repeats", False))
    return run_curl_probe_with_repeats(
        req,
        repeats=repeats,
        parallel_repeats=parallel,
        repeats_mode=str(payload.get("repeats_mode", "fast")),
        quick_break=bool(payload.get("quick_break", False)),
    )


def run_udp_worker_probe(ip: str, port: int, timeout: float, try_burst: bool = False) -> dict:
    """Run a UDP voice probe → result dict (former _probe_worker.run_probe)."""
    from blockchecks.checkers.udp_voice import voice_udp_probe

    ok, lat, detail, method = voice_udp_probe(ip, port, timeout, try_burst=try_burst)
    return {
        "success": ok,
        "latency_ms": round(lat, 1),
        "detail": detail,
        "method": method,
        "burst": try_burst,
    }


def _run_curl_worker_stdio_loop(argv_payload: str | None = None) -> int:
    """JSON-lines curl worker: one request line in, one response line out."""
    _FAIL = {
        "success": False,
        "http_code": 0,
        "latency_ms": 0,
        "content_len": 0,
        "content_ok": False,
        "throttled": False,
        "read_rate_bps": 0,
    }

    def _emit(payload: dict) -> None:
        print(json.dumps(payload), flush=True)

    def _handle(raw: str) -> None:
        line = raw.strip()
        if not line:
            return
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            _emit({**_FAIL, "error": f"bad request json: {exc}"[:120]})
            return
        try:
            _emit(run_curl_worker_payload(payload))
        except Exception as exc:
            log.warning("curl worker payload failed: %s", exc)
            _emit({**_FAIL, "error": str(exc)[:120]})

    if argv_payload:
        _handle(argv_payload)
    for raw in sys.stdin:
        _handle(raw)
    return 0


def _dispatch_worker_main(argv: list[str] | None = None) -> int:
    """Dispatch subprocess invocation by ``--mode`` (curl|udp)."""
    args = argv if argv is not None else list(sys.argv[1:])
    mode = "curl"
    if "--mode" in args:
        i = args.index("--mode")
        if i + 1 < len(args):
            mode = args[i + 1]
            args = [a for a in args if a != "--mode"]
            # remove the mode value too
            args = [a for a in args if a not in ("curl", "udp")]
    if mode == "udp":
        try_burst = "--burst" in args
        args = [a for a in args if a != "--burst"]
        if len(args) != 3:
            print(
                "usage: python -m blockchecks.engine.in_ns_workers --mode udp IP PORT TIMEOUT [--burst]",
                file=sys.stderr,
            )
            return 2
        ip, port_s, timeout_s = args
        data = run_udp_worker_probe(ip, int(port_s), float(timeout_s), try_burst=try_burst)
        print(json.dumps(data))
        return 0
    # curl mode — JSON-lines on stdin (or one-shot argv[0] for back-compat)
    argv_payload = args[0] if args else None
    if argv_payload is None and sys.stdin.isatty():
        print(
            "usage: echo JSON | python -m blockchecks.engine.in_ns_workers --mode curl",
            file=sys.stderr,
        )
        return 2
    return _run_curl_worker_stdio_loop(argv_payload)


if __name__ == "__main__":
    raise SystemExit(_dispatch_worker_main())
