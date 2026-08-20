"""Stop an active full / scan / pair campaign."""

from __future__ import annotations

import logging

from blockchecks.service.run_control import request_graceful_stop

log = logging.getLogger(__name__)


def cmd_stop(args) -> int:
    code, message = request_graceful_stop(
        force=bool(getattr(args, "force", False)),
        wait_sec=float(getattr(args, "wait", 120.0)),
    )
    log.info("%s", f"  {message}")
    return code
