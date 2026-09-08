"""Shared curl_cffi Session helpers (no checker imports — avoids cycles)."""

from __future__ import annotations

import logging

import curl_cffi

log = logging.getLogger(__name__)


def apply_no_env_proxy(session: curl_cffi.Session) -> None:
    """Neutralize http(s)_proxy environment for this Session.

    libcurl reads ``http_proxy``/``HTTPS_PROXY`` env when CURLOPT_PROXY is
    unset, and sudo-spawned probes inherit an operator HTTP(S)_PROXY from
    /etc/environment (pam_env) — inside a netns that proxy is 127.0.0.1
    (dead) and every probe fails with curl(7). ``curl_cffi`` drops empty
    ``proxy=`` constructor values (verified in-netns 0.16.1), so the explicit
    empty setopt is the only reliable switch. The only sanctioned proxy is
    the gv/ytcdn variant's socks5, applied per-request via
    ``curl_probe._curl_proxy_kwargs`` (request-level wins over this).
    """
    try:
        session.curl.setopt(curl_cffi.CurlOpt.PROXY, "")
    except Exception as exc:  # noqa: BLE001 — exotic builds may lack the option
        log.debug("proxy env neutralization skipped: %s", exc)
