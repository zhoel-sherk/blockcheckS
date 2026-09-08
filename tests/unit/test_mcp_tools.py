

def test_strip_applied_clause_paren_aware():
    # AUDIT §12: compound §5.3 predicate nests a group — literal replace
    # used to leave broken SQL behind.
    from blockchecks.mcp.server import _strip_applied_clause

    compound = (
        " WHERE s.proto='tcp' AND ((t.status='PASS' AND (t.bridge_applied IS NULL"
        " OR t.bridge_applied = 1)) OR (t.status='THROTTLED' AND t.bridge_applied = 1))"
    )
    stripped = _strip_applied_clause(compound)
    assert "bridge_applied" not in stripped
    assert "t.status='PASS'" not in stripped
    assert "t.status='THROTTLED'" not in stripped
    assert "WHERE s.proto='tcp'" in stripped

    simple = "SELECT 1 FROM tcp_results WHERE status='PASS' AND (bridge_applied IS NULL OR bridge_applied = 1)"
    assert "bridge_applied" not in _strip_applied_clause(simple)
    # unrelated AND-groups must survive
    keep = "WHERE a=1 AND (b=2 OR c=3) AND d=4"
    assert _strip_applied_clause(keep) == keep
