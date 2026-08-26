"""MCP tool names in docs stay in sync with @mcp.tool() in server.py."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[2]
SERVER_PY = REPO / "src/blockchecks/mcp/server.py"
API_MD = REPO / "docs/api.md"
MCP_MD = REPO / "docs/mcp.md"

# Must match AST discovery in test_mcp_tool_count_matches_expected.
EXPECTED_MCP_TOOL_COUNT = 22


def _collect_mcp_tool_names() -> list[str]:
    tree = ast.parse(SERVER_PY.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            if not isinstance(deco, ast.Call):
                continue
            func = deco.func
            if isinstance(func, ast.Attribute) and func.attr == "tool":
                names.append(node.name)
    return sorted(names)


def _doc_mentions(name: str, text: str) -> bool:
    return f"`{name}`" in text


@pytest.fixture(scope="module")
def mcp_tools() -> list[str]:
    tools = _collect_mcp_tool_names()
    assert tools, f"no @mcp.tool() functions found in {SERVER_PY}"
    return tools


def test_mcp_tool_count_matches_expected(mcp_tools: list[str]) -> None:
    assert len(mcp_tools) == EXPECTED_MCP_TOOL_COUNT, mcp_tools


def test_api_md_tool_count_and_names(mcp_tools: list[str]) -> None:
    text = API_MD.read_text(encoding="utf-8")
    match = re.search(r"Реализовано \*\*(\d+) инструмент", text)
    assert match, "api.md §6 missing MCP tool count line"
    assert int(match.group(1)) == len(mcp_tools)
    missing = [t for t in mcp_tools if not _doc_mentions(t, text)]
    assert not missing, f"api.md missing MCP tools: {missing}"


def test_mcp_md_lists_all_tools(mcp_tools: list[str]) -> None:
    text = MCP_MD.read_text(encoding="utf-8")
    missing = [t for t in mcp_tools if not _doc_mentions(t, text)]
    assert not missing, f"mcp.md missing MCP tools: {missing}"


def test_api_md_get_log_tail_sources_not_live() -> None:
    """get_log_tail uses LOG_SOURCES only; live probes are get_live_events."""
    section = API_MD.read_text(encoding="utf-8").split("## 6. MCP-инструменты", 1)[1]
    section = section.split("## 7.", 1)[0]
    assert "`get_live_events`" in section
    tail_line = next(
        (line for line in section.splitlines() if "get_log_tail" in line and "читает" in line),
        "",
    )
    assert tail_line, "api.md §6 missing get_log_tail source line"
    channels = tail_line.split("LOG_SOURCES", 1)[0]
    assert "`python`" in channels and "`campaign`" in channels and "`nfqws2`" in channels
    assert "`live`" not in channels
