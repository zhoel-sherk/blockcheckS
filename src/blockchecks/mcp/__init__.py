"""FastMCP bridge to the bs serve daemon.
mcp is an optional extra; main() imports it lazily so bs --help works without it.
"""

from __future__ import annotations

__all__ = ["main"]


def main() -> int:
    """Entry point for ``bs-mcp`` / ``bs mcp`` (stdio transport)."""
    import sys

    try:
        from blockchecks.mcp.server import main as _run
    except ImportError:
        print(  # noqa: print
            "Missing optional dependency 'mcp'.\n"
            "Install: pip install 'blockchecks[mcp]'\n"
            "or:\n"
            "    pip install -r requirements-mcp.txt",
            file=sys.stderr,
        )
        return 1
    return _run()
