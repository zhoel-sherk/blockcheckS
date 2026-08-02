# Package structure — blockcheckS

Аудит layout после packaging + onboarding split (2026-08).

## Канон

```
blockcheckS/
├── src/blockchecks/
│   ├── __init__.py
│   ├── bs.py                  # thin CLI entry → cli.parser.main
│   ├── cli/
│   │   ├── parser.py          # argparse + dispatch
│   │   ├── presets.py
│   │   └── commands/          # tcp, udp, pair
│   ├── main.py                # bs full orchestrator
│   ├── nfconf.py
│   ├── engine/
│   │   ├── paths.py           # XDG dirs (config/data/cache)
│   │   ├── store/             # RunStateStore DAO (sqlite)
│   │   ├── config.py
│   │   ├── generators/        # StrategyItem + Standard/Flowseal/Custom
│   │   ├── matrix_generator.py  # facade: generate_tcp/udp
│   │   ├── async_runner.py
│   │   ├── test_runner.py
│   │   ├── _probe_worker.py   # subprocess curl probe (no sys.path hack)
│   │   └── ...
│   └── checkers/
├── configs/                   # repo-root .conf (CONFIGS_DIR)
├── presets/
├── tests/
├── docs/
└── pyproject.toml
```

Entry points: `bs` → `blockchecks.bs:main`, `bc-main`, `bc-nfconf`.

## Path resolution & configs policy (ONB-7)

**Recommended:** `pip install -e .` from git checkout.

`PROJECT_DIR` in `config.py` resolves repo root (parent of `src/`). Runtime paths:

- `configs/*.conf` — repo root only (`PROJECT_DIR`)
- `presets/` — repo root (shipped catalog)
- **Runtime data (XDG):**
  - `~/.config/blockcheckS/config.toml` — user defaults
  - `~/.local/state/blockcheckS/state.db` — run state DB (default `--db`)
  - `~/.local/state/blockcheckS/export/` — nfconf export (default `--out-dir` for `bs full`)
  - `~/.local/state/blockcheckS/logs/`, `shortlists/`, `presets/` — runtime artifacts
  - `~/.cache/blockcheckS/` — gv/voice/settle caches, blob-cache, isolated `pycache/`
  - `~/.local/share/blockcheckS/` — reserved (`DATA_DIR`; created by `ensure_dirs()`)

Override: CLI args > `BLOCKCHECKS_*` env > `config.toml` > XDG defaults.
See [`engine/paths.py`](../src/blockchecks/engine/paths.py) and [`settings.example.toml`](../settings.example.toml).

Legacy CWD-relative `--db state.db` still works when passed explicitly.

`MANIFEST.in` includes `configs/*.conf` in **sdist** for source distributions.
Plain `pip install` wheel without checkout may not find configs — use editable
install or clone repo. This is intentional (not the same as **BLOB-1**
`presets/blobs/` manifest).

## Import graph

```
bs ──► cli.parser ──► commands + async_runner / test_runner
main ──► async_runner + nfconf
async_runner ──► _probe_worker / checkers + netns_pool + nfqws2
matrix_generator ──► generators/* (facade)
```

Canonical pair path: `bs pair` → `async_runner` (not `pair_runner`).

## Public API

Re-exported from `blockchecks.engine` and `blockchecks.checkers` — see
[architecture.md](architecture.md).

## Quality

```bash
pip install -e ".[dev,discovery]"
ruff check src tests
pytest -m "not integration"
```

## Deprecated

- `tmp-scripts/README.md` architecture section → use [architecture.md](architecture.md)
- `pair_runner.py` — legacy; do not extend
- `engine/db_logger.py` — re-export shim; use `engine/store/`
