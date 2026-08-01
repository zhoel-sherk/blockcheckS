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

## 3. Environment alternative

For machine-specific paths, prefer `BLOCKCHECKS_*` in
[`engine/config.py`](../src/blockchecks/engine/config.py) over new flags.
Document in [`settings.example.env`](../../settings.example.env).

## 4. Tests

- `tests/unit/test_package_structure.py` — `bs --help` exits 0
- Add regression in `test_audit_regressions.py` if flag affects resume/matrix

## 5. Docs

Update [guide.md](../guide.md) examples if user-facing.
