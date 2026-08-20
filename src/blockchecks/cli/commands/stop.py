"""Stop an active full / scan / pair campaign."""

from __future__ import annotations

from blockchecks.service.run_control import request_graceful_stop


def cmd_stop(args) -> int:
    code, message = request_graceful_stop(
        force=bool(getattr(args, "force", False)),
        wait_sec=float(getattr(args, "wait", 120.0)),
    )
    print(f"  {message}")
    return code
