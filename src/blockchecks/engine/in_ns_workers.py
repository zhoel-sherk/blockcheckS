"""In-namespace nfqws2 probe workers (split out of async_runner god-file, day-5).

Synchronous functions called via asyncio.to_thread from AsyncTestRunner:
start nfqws2 in a netns, run curl/STUN/HTTP3 probe, return result dict.
"""

from __future__ import annotations

import json
import os
import subprocess as sp

from blockchecks.checkers.curl_probe import (
    CurlProbeRequest,
    is_googlevideo_domain,
    is_ytcdn_domain,
    prepare_googlevideo_probe,
    prepare_ytcdn_probe,
    worker_wall_timeout,
    ytcdn_probe_variants,
)
from blockchecks.engine.config import (
    BLOB_DIR,
    NFQUEUE_TCP,
    NFQUEUE_UDP,
    PYTHON_BIN,
    get_lua_init_scripts,
)
from blockchecks.engine.nfqws_config import (
    _add_blobs_from_strategy,
    _build_inline_nfqws_lines,
    _build_quic_nfqws_lines,
    _split_cli_args,
    _sudo,
)
from blockchecks.service.nfqws2 import start_daemon as _nfqws2_daemon
from blockchecks.service.probe import (
    invoke_curl_probe_worker as _invoke_curl_probe_worker,
)
from blockchecks.service.probe import probe_request_dict as _probe_request_dict

# Budget for retry-on-next-IP attempts after the first failed IP (keeps
# throttled-IP worst case from N×timeout, see per-IP throttling).
RETRY_IP_TIMEOUT = 2.0


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
    py = python_bin or PYTHON_BIN
    tmp_conf = None

    if is_config:
        import shutil
        import tempfile as _tf

        src = os.path.abspath(strategy) if not os.path.isabs(strategy) else strategy
        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_quic_", suffix=".conf")
        os.close(_tf_fd)
        shutil.copy2(src, tmp_conf)
        _nfqws2_daemon(ns_name, tmp_conf)
    else:
        import tempfile as _tf

        config_lines = _build_quic_nfqws_lines(strategy)
        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_quic_", suffix=".conf")
        os.close(_tf_fd)
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        _nfqws2_daemon(ns_name, tmp_conf)

    # Flush OUTPUT first: fallback variants re-enter this function in the same
    # netns and would otherwise stack duplicate NFQUEUE rules.
    _sudo("ip", "netns", "exec", ns_name, "iptables", "-F", "OUTPUT")
    _sudo(
        "ip",
        "netns",
        "exec",
        ns_name,
        "iptables",
        "-A",
        "OUTPUT",
        "-p",
        "udp",
        "--dport",
        "443",
        "-j",
        "NFQUEUE",
        "--queue-num",
        str(NFQUEUE_UDP),
        "--queue-bypass",
    )

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
            ["sudo", "ip", "netns", "exec", ns_name, py, "-c", check_code],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
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
    finally:
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
    """Fallback chain for a QUIC strategy that was dropped (timeout).

    fake-инъекции пробивают ТСПУ (доходят до CDN — диагностика 2026-08),
    тогда как split/disorder (ipfrag) дропаются. Порядок: базовый fake →
    +badsum → +ip_ttl=1. Стратегии уже содержащие badsum/ip_ttl не дублируются.
    ``BLOCKCHECKS_QUIC_FALLBACK=0`` disables the fallback.
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
        settle_elapsed = _nfqws2_daemon(
            ns_name, tmp_conf, settle_max=settle_max, settle_poll=settle_poll
        )
    else:
        config_lines = _build_inline_nfqws_lines(strategy, protocol, extra_lua_desync)
        import tempfile as _tf

        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_", suffix=".conf")
        os.close(_tf_fd)
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        settle_elapsed = _nfqws2_daemon(
            ns_name, tmp_conf, settle_max=settle_max, settle_poll=settle_poll
        )

    _sudo(
        "ip",
        "netns",
        "exec",
        ns_name,
        "iptables",
        "-A",
        "OUTPUT",
        "-p",
        "tcp",
        "--dport",
        dport,
        "-j",
        "NFQUEUE",
        "--queue-num",
        str(NFQUEUE_TCP),
        "--queue-bypass",
    )

    probe_req.timeout = timeout
    # Retry-on-next-IP (IP-PIN): when the resolved IP fails but nfqws2 is already
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
                    "request": _probe_request_dict(variant),
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
                data = _invoke_curl_probe_worker(ns_name, py, payload, wall)
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
    if not domains:
        return {}
    py = python_bin or PYTHON_BIN
    is_http = protocol == "http"
    dport = "80" if is_http else "443"
    tmp_conf = None
    resolved_ips = dict(resolved_ips or {})
    gv_fail: dict[str, dict] = {}
    probe_requests: list[CurlProbeRequest] = []

    for d in domains:
        if not is_http and is_googlevideo_domain(d):
            req, err = prepare_googlevideo_probe(d, resolved_ip=resolved_ips.get(d))
            if err:
                gv_fail[d] = err
                continue
            if req.resolved_ip:
                resolved_ips[d] = req.resolved_ip
            probe_requests.append(req)
        elif not is_http and is_ytcdn_domain(d):
            req, err = prepare_ytcdn_probe(d, resolved_ip=resolved_ips.get(d))
            if err:
                gv_fail[d] = err
                continue
            if req.resolved_ip:
                resolved_ips[d] = req.resolved_ip
            probe_requests.append(req)
        else:
            probe_requests.append(
                CurlProbeRequest(
                    domain=d,
                    timeout=timeout,
                    resolved_ip=resolved_ips.get(d),
                    resolve_name=d.split("/")[0],
                    disable_ech=disable_ech,
                    protocol=protocol,
                )
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
        settle_elapsed = _nfqws2_daemon(
            ns_name, tmp_conf, settle_max=settle_max, settle_poll=settle_poll
        )
    else:
        import tempfile as _tf

        config_lines = _build_inline_nfqws_lines(strategy, protocol, extra_lua_desync)
        _tf_fd, tmp_conf = _tf.mkstemp(prefix="bs_async_multi_", suffix=".conf")
        os.close(_tf_fd)
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        settle_elapsed = _nfqws2_daemon(
            ns_name, tmp_conf, settle_max=settle_max, settle_poll=settle_poll
        )

    _sudo(
        "ip",
        "netns",
        "exec",
        ns_name,
        "iptables",
        "-A",
        "OUTPUT",
        "-p",
        "tcp",
        "--dport",
        dport,
        "-j",
        "NFQUEUE",
        "--queue-num",
        str(NFQUEUE_TCP),
        "--queue-bypass",
    )

    for req in probe_requests:
        req.timeout = timeout

    payload = {
        "mode": "batch",
        "requests": [_probe_request_dict(r) for r in probe_requests],
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
        raw = _invoke_curl_probe_worker(ns_name, py, payload, wall)
        settle_ms = round(settle_elapsed * 1000, 1)
        out = {d: {**raw.get(d, {}), "settle_ms": settle_ms} for d in domains_active}
        # Retry-on-next-IP for failed domains (IP-PIN): nfqws2 is already up, so
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
                        "request": _probe_request_dict(req),
                        "repeats": max(1, int(repeats)),
                        "parallel_repeats": False,
                        "repeats_mode": repeats_mode,
                        "quick_break": bool(quick_break),
                    }
                    retry_wall = worker_wall_timeout(
                        req.timeout, repeats, n_domains=1, curl_parallel=1
                    )
                    retry = _invoke_curl_probe_worker(ns_name, py, retry_payload, retry_wall)
                    retry["settle_ms"] = settle_ms
                    retry["used_ip"] = ip
                    out[d] = retry
                    if retry.get("success") or attempt == len(remaining) - 1:
                        break
        out.update(gv_fail)
        return out
    finally:
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

    coexist=True: do not pkill existing nfqws2 (keep TCP desync for pairs).
    """

    py = python_bin or PYTHON_BIN
    kill_existing = not coexist
    tmp_conf = None

    if is_config:
        src = os.path.abspath(strategy) if not os.path.isabs(strategy) else strategy
        import shutil
        import tempfile as _tf2

        _tf2_fd, tmp_conf = _tf2.mkstemp(prefix="bs_async_udp_", suffix=".conf")
        os.close(_tf2_fd)
        shutil.copy2(src, tmp_conf)
        _nfqws2_daemon(ns_name, tmp_conf, kill_existing=kill_existing)
    elif strategy.strip().startswith("--"):
        # Full CLI config (standard_udp dual-blob etc.)
        config_lines = [
            f"--qnum={NFQUEUE_UDP}",
            "--filter-l3=ipv4",
            "--ipcache-lifetime=0",
            "--bind-fix4",
        ]
        for lua in get_lua_init_scripts():
            if os.path.exists(lua):
                config_lines.append(f"--lua-init=@{lua}")
        for raw_line in strategy.split("\n"):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            config_lines.extend(_split_cli_args(raw_line))
        import tempfile as _tf2

        _tf2_fd, tmp_conf = _tf2.mkstemp(prefix="bs_async_udp_", suffix=".conf")
        os.close(_tf2_fd)
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        _nfqws2_daemon(ns_name, tmp_conf, kill_existing=kill_existing)
    else:
        # Inline lua-desync core (e.g. fake:blob=discord_udp:repeats=6)
        config_lines = [
            f"--qnum={NFQUEUE_UDP}",
            "--filter-udp=50000-50100",
            "--filter-l3=ipv4",
            "--ipcache-lifetime=0",
            "--bind-fix4",
        ]
        for lua in get_lua_init_scripts():
            if os.path.exists(lua):
                config_lines.append(f"--lua-init=@{lua}")
        _add_blobs_from_strategy(config_lines, strategy)
        if not any(line.startswith("--blob=") for line in config_lines):
            blob = os.path.join(BLOB_DIR, "discord_udp.bin")
            if os.path.exists(blob):
                config_lines.append(f"--blob=discord_udp:@{blob}")
        for raw_line in strategy.split("\n"):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            if raw_line.startswith("--"):
                config_lines.extend(_split_cli_args(raw_line))
            else:
                config_lines.append(f"--lua-desync={raw_line}")
        import tempfile as _tf2

        _tf2_fd, tmp_conf = _tf2.mkstemp(prefix="bs_async_udp_", suffix=".conf")
        os.close(_tf2_fd)
        with open(tmp_conf, "w") as f:
            f.write("\n".join(config_lines))
        _nfqws2_daemon(ns_name, tmp_conf, kill_existing=kill_existing)

    _sudo(
        "ip",
        "netns",
        "exec",
        ns_name,
        "iptables",
        "-A",
        "OUTPUT",
        "-p",
        "udp",
        "--dport",
        str(port),
        "-j",
        "NFQUEUE",
        "--queue-num",
        str(NFQUEUE_UDP),
        "--queue-bypass",
    )

    probe_code = f"""
import json, os
from blockchecks.checkers.udp_voice import voice_udp_probe
_burst = os.environ.get("BLOCKCHECKS_VOICE_BURST", "").strip().lower() in ("1","true","on","yes")
ok, lat, detail, method = voice_udp_probe({ip!r}, {port}, {timeout}, try_burst=_burst)
print(json.dumps({{"success": ok, "latency_ms": lat,
    "detail": detail, "method": method}}))
"""
    try:
        r = sp.run(
            ["sudo", "ip", "netns", "exec", ns_name, py, "-c", probe_code],
            capture_output=True,
            text=True,
            timeout=timeout + 3,
        )
        try:
            return json.loads(r.stdout)
        except json.JSONDecodeError:
            return {"success": False, "latency_ms": 0, "detail": "parse error"}
    finally:
        if tmp_conf:
            try:
                os.unlink(tmp_conf)
            except OSError:
                pass


# ── AsyncTestRunner ─────────────────────────────────


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
    except Exception:
        pass

