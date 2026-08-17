"""``bs serve`` — resident probe server command.

Unix-socket core (asyncio.start_unix_server, no deps) + optional authenticated
HTTP bridge on 127.0.0.1 (Bearer token, see ``--http-token``). Fair exclusion
with long-term campaigns: while a campaign owns run.lock, every probe request
returns busy/campaign_active (423-style) instead of blocking.
"""

from __future__ import annotations

import asyncio

from blockchecks.service.probe_service import ProbeService
from blockchecks.service.run_control import read_active_run, run_session
from blockchecks.service.server import ProbeServer


def _resolve_http_token(args) -> str | None:
    """CLI --http-token > env BLOCKCHECKS_HTTP_TOKEN > config.toml [http] token."""
    import os

    explicit = getattr(args, "http_token", None)
    if explicit:
        return str(explicit)
    from_env = os.environ.get("BLOCKCHECKS_HTTP_TOKEN")
    if from_env:
        return from_env
    try:
        from blockchecks.cli.user_config import load_user_config

        cfg = load_user_config()
        http_cfg = cfg.get("http") or {}
        if isinstance(http_cfg, dict) and http_cfg.get("token"):
            return str(http_cfg["token"])
    except Exception:  # noqa: BLE001
        pass
    return None


def cmd_serve(args) -> int:
    pool = int(getattr(args, "pool", 0) or 0) or None
    service = ProbeService(
        pool_size=pool,
        lua_bridge=not bool(getattr(args, "classic", False)),
        bridge_batch=int(getattr(args, "bridge_batch", 500) or 500),
        default_timeout=float(getattr(args, "timeout", 3.0) or 3.0),
    )
    server = ProbeServer(service)

    # Fair exclusion startup check: refuse to start if a campaign is active.
    active = read_active_run()
    if active is not None:
        print(
            f"  [serve] active campaign: {active.command} (pid {active.pid}). "
            "Start serve when the campaign is done, or use it after --resume finishes."
        )
        return 2

    async def _run() -> int:
        # Register run.lock as "serve" so long-term campaigns refuse to start
        # while the service holds the pool (mutual exclusion through one lock).
        async with run_session("serve", argv=["serve"]):
            try:
                await service.start()
                print(
                    f"  [serve] pool ready ({service.pool_size} netns), "
                    f"lua_bridge={service.lua_bridge}"
                )
                http_port = getattr(args, "http_port", None)
                if http_port:
                    http_token = _resolve_http_token(args)
                    if not http_token:
                        print("  [serve] WARNING: --http-port set but no token (--http-token / env "
                              "BLOCKCHECKS_HTTP_TOKEN / config.toml [http] token). HTTP bridge disabled.")
                    await asyncio.gather(
                        server.serve(),
                        server.serve_http(port=int(http_port), token=http_token),
                    )
                else:
                    await server.serve()
            finally:
                await service.stop()
        return 0

    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:
        print("\n  [serve] stopped")
        return 0
