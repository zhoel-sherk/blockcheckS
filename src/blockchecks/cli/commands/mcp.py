"""``bs mcp`` — Model Context Protocol server (stdio).

Spawns the FastMCP server over STDIN/STDOUT so local LLM clients
(Claude Desktop, Cursor, opencode) can drive the resident ``bs serve``
daemon via Unix socket.

The ``mcp`` dependency is optional (``blockchecks[mcp]``). If it is missing
we degrade gracefully: a clear install hint and exit code 1 — the base
runtime and other commands are unaffected.
"""

from __future__ import annotations

import sys


def cmd_mcp(_args) -> int:
    try:
        from blockchecks.mcp import main as mcp_main
    except ImportError:
        print(
            "Ошибка: зависимость 'mcp' не найдена.\n"
            "Для использования MCP-сервера установите пакет с экстра-зависимостями:\n"
            "    pip install 'blockchecks[mcp]'\n"
            "или:\n"
            "    pip install -r requirements-mcp.txt",
            file=sys.stderr,
        )
        return 1
    return mcp_main()
