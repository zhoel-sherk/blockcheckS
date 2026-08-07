"""Dependency layer enforcement — rules from [tool.blockchecks.architecture]."""

from __future__ import annotations

import pytest
from pytest_archon import archrule
from tests.unit._quality_config import tool_section

pytestmark = [pytest.mark.unit, pytest.mark.quality]


def _get_rules() -> list[dict]:
    cfg = tool_section("tool", "blockchecks", "architecture")
    rules = cfg.get("rules") or []
    assert rules, "pyproject [tool.blockchecks.architecture.rules] is empty"
    return rules

def _get_package() -> str:
    cfg = tool_section("tool", "blockchecks", "architecture")
    return cfg.get("package") or "blockchecks"


@pytest.mark.parametrize("rule", _get_rules(), ids=lambda r: r["name"])
def test_architecture_layers_from_pyproject(rule: dict) -> None:
    package = _get_package()
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
