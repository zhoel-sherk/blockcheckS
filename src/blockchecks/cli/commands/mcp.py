"""bs mcp: FastMCP over stdio.
mcp is optional (blockchecks[mcp]). If missing, print an install hint and exit 1.
"""

from __future__ import annotations

import sys


def cmd_mcp(_args) -> int:
    try:
        from blockchecks.mcp import main as mcp_main
    except ImportError:
        print(
            "Missing optional dependency 'mcp'.\n"
            "Install: pip install 'blockchecks[mcp]'\n"
            "or:\n"
            "    pip install -r requirements-mcp.txt",
            file=sys.stderr,
        )
        return 1
    return mcp_main()
