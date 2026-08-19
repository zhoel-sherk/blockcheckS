# Cookbook: add a CLI flag

CLI lives in [`src/blockchecks/cli/`](../src/blockchecks/cli/) (entry point `bs`).

## Campaign commands (`scan`, `pair`, `full`)

Shared flags for matrix campaigns are registered via `add_campaign_args()` in
[`cli/parser.py`](../src/blockchecks/cli/parser.py). When adding a flag that
applies to all three commands, add it there (with `mode` guards as needed) —
do not duplicate per-command parsers.

Run profiles (`--profile smoke|fast|20h`) are defined in
[`cli/profiles.py`](../src/blockchecks/cli/profiles.py); extend `PROFILES` dict
and `apply_profile()` if adding a new profile.

Typed config propagation: handlers should build `RunSpec.from_args(args)` and
pass via `CampaignContext` (see [`engine/run_spec.py`](../src/blockchecks/engine/run_spec.py)).

## 1. Add argparse option

In [`cli/parser.py`](../src/blockchecks/cli/parser.py), add to the relevant subparser
or to `add_campaign_args()` / a shared helper (`add_adaptive_args`, `add_secure_dns_args`, …):

```python
p.add_argument("--my-flag", action="store_true", help="...")
```

For `bs full`, campaign flags live in `add_campaign_args(parser, mode="full")`;
`main.py` calls the same helper — no separate duplicate parser.

> **pydantic CliApp negation (1.3.x):** the main `bs` entry parses via
> pydantic-settings `CliApp` (models derived from parser actions). A flag named
> `--no-xxx` is parsed by pydantic as a *negation* (always False). If you add a
> genuinely-named `--no-<field>` flag, register it in `_NO_PREFIX_FIELDS`
> (`cli/cliapp.py`), or it will silently never become True.

> **Inverse / protective defaults (1.3.7):** features like AQ, preflight, ECH,
> and wssize are ON by default. Add `--no-<feature>` to disable; keep a positive
> alias only when backward compatibility requires it (e.g. `--adaptive` →
> `dest="no_adaptive", action="store_false"`).

## 2. Propagate to runner

| Command | Propagate to |
|---------|--------------|
| `scan`, `pair` | `cmd_pair` / `RunSpec.from_args` → `AsyncTestRunner` kwargs |
| `full` | `main.py` → `RunSpec.from_args` → `CampaignContext` → `run_full()` |
| `tcp`, `udp` | `cmd_tcp` / `TestRunner` |

Use `getattr(args, "my_flag", False)` for optional flags on shared parsers.

## 3. Paths and user config

Path defaults come from [`engine/paths.py`](../src/blockchecks/engine/paths.py)
(XDG layout). Shared store flags: `add_store_args()` in `parser.py`.

User overrides: `~/.config/blockcheckS/config.toml` via
[`cli/user_config.py`](../src/blockchecks/cli/user_config.py) — loaded in
`cliapp.main()` (`load_user_config` → `apply_parser_defaults` → `build_cli_root`);
`finalize_store_args()` fills `db`/`out_dir` from `[paths]`/XDG on the CliApp path.

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
