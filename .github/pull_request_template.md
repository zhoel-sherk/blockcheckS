## Summary

<!-- What changed and why -->

## Test plan

- [ ] `ruff check src tests`
- [ ] `pytest -m "not integration"`
- [ ] `bs --help` (smoke)

## Checklist

- [ ] No secrets committed (`settings.ini`, `token.txt`, `state.db`)
- [ ] Docs updated if CLI/API changed
- [ ] Editable install (`pip install -e .`) for `configs/` access
