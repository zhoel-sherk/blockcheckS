"""blockcheckS MCP package — FastMCP bridge over the resident ``bs serve`` daemon.

Optional extra: ``pip install blockchecks[mcp]``. The module itself stays
importable without the ``mcp`` package (lazy import inside ``main()``) so the
base runtime and ``bs --help`` never break on a missing optional dependency.
"""

from __future__ import annotations

__all__ = ["main"]


def main() -> int:
    """Entry point for ``bs-mcp`` / ``bs mcp`` (stdio transport)."""
    import sys

    try:
        from blockchecks.mcp.server import main as _run
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
    return _run()
