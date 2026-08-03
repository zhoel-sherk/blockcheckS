"""Dependency layer enforcement — rules from [tool.blockchecks.architecture]."""

from __future__ import annotations

import pytest
from pytest_archon import archrule
from tests.unit._quality_config import tool_section

pytestmark = [pytest.mark.unit, pytest.mark.quality]


def test_architecture_layers_from_pyproject() -> None:
    cfg = tool_section("tool", "blockchecks", "architecture")
    package = cfg.get("package") or "blockchecks"
    rules = cfg.get("rules") or []
    assert rules, "pyproject [tool.blockchecks.architecture.rules] is empty"

    for rule in rules:
        name = rule["name"]
        match = rule["match"]
        forbidden = list(rule.get("should_not_import") or [])
        assert forbidden, f"rule {name!r} has empty should_not_import"
        (
            archrule(name, comment=f"from pyproject: {name}")
            .match(match)
            .should_not_import(*forbidden)
            .check(package)
        )
