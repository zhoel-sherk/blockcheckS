# Cookbook: add a CLI flag

CLI lives in [`src/blockchecks/cli/`](../src/blockchecks/cli/) (entry point `bs`).

## 1. Add argparse option

In [`cli/parser.py`](../src/blockchecks/cli/parser.py), add to the relevant subparser:

```python
p.add_argument("--my-flag", action="store_true", help="...")
```

For `bs full`, also add to [`main.py`](../src/blockchecks/main.py) parser if not shared.

## 2. Propagate to runner

| Command | Propagate to |
|---------|--------------|
| `scan`, `pair` | `cmd_pair` / `AsyncTestRunner` kwargs |
| `full` | `main.py` → `run_full()` |
| `tcp`, `udp` | `cmd_tcp` / `TestRunner` |

Use `getattr(args, "my_flag", False)` for optional flags on shared parsers.

## 3. Paths and user config

Path defaults come from [`engine/paths.py`](../src/blockchecks/engine/paths.py)
(XDG layout). Shared store flags: `add_store_args()` in `parser.py`.

User overrides: `~/.config/blockcheckS/config.toml` via
[`cli/user_config.py`](../src/blockchecks/cli/user_config.py) — loaded in
`parser.main()` before `parse_args`.

For machine-specific tool paths, prefer `BLOCKCHECKS_*` in
[`engine/config.py`](../src/blockchecks/engine/config.py) or `[tools]` in
`config.toml`. Document in [`settings.example.toml`](../../settings.example.toml).

## 4. Tests

- `tests/unit/test_package_structure.py` — `bs --help` exits 0
- New flag must be **read** in the command handler (or shared helper). The quality gate
  `pytest -m quality` → `test_dead_cli_flags` fails on unused dests.
- Policy: `[tool.blockchecks.dead_flags]` in `pyproject.toml` (readers / allow / parity_dests).
- Typed env/TOML: `[tool.blockchecks.settings]` + `engine/settings.py` (`BlockchecksSettings`).
- Add regression in `test_audit_regressions.py` if flag affects resume/matrix

## 5. Docs

Update [guide.md](../guide.md) examples if user-facing.
