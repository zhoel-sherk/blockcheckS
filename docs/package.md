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
  - `~/.config/blockcheckS/presets/` — reserved (`USER_PRESETS_DIR`)
  - `~/.local/state/blockcheckS/state.db` — run state DB (default `--db`)
  - `~/.local/state/blockcheckS/logs/` — runtime logs
  - `~/.local/state/blockcheckS/presets/` — reserved (`USER_DATA_PRESETS_DIR`)
  - `~/.local/share/blockcheckS/export/` — nfconf export (default `--out-dir`; 1.0.x legacy: `state/.../export`)
  - `~/.local/share/blockcheckS/shortlists/` — shortlist JSON (legacy under `state/`)
  - `~/.local/share/blockcheckS/zapret2/` — optional auto-fetched vendor tree
  - `~/.cache/blockcheckS/` — gv/voice/settle caches, blob-cache, isolated `pycache/`

Override: CLI args > `config.toml` `[paths]` > XDG / `BLOCKCHECKS_*_HOME` defaults.
For tools: CLI / env `BLOCKCHECKS_*` > `[tools]` > built-in.
See [`engine/paths.py`](../src/blockchecks/engine/paths.py) and [`settings.example.toml`](../settings.example.toml).

Legacy CWD-relative `--db state.db` still works when passed explicitly.

`MANIFEST.in` includes `configs/*.conf` in **sdist** for source distributions.
Plain `pip install` wheel without checkout may not find configs — use editable
install or clone repo. This is intentional (not the same as **BLOB-1**
`presets/blobs/` manifest).

### Tools / zapret2 vendor (1.0.1)

Resolution for `nfqws2`: `BLOCKCHECKS_NFQWS2` → `PATH` → `/opt/zapret2/nfq2/nfqws2`
→ `~/.local/share/blockcheckS/bin/nfqws2`. If missing and fetch enabled (default),
`engine/system_deps.py` downloads the latest `bol-van/zapret2` release (sha256)
into `~/.local/share/blockcheckS/zapret2/` and sets `BLOCKCHECKS_BLOBS` /
`BLOCKCHECKS_LUA_DIR`. Cache: `~/.cache/blockcheckS/zapret2-dl/`.

Flags: `--no-fetch-deps`, `--offline`, `--skip-deps-check`.

## Import graph

```
bs ──► cli.parser ──► commands + async_runner / test_runner
main ──► async_runner + nfconf
async_runner ──► _probe_worker / checkers + netns_pool + nfqws2
matrix_generator ──► generators/* (facade)
```

Canonical pair path: `bs pair` → `async_runner`.

## Public API

Re-exported from `blockchecks.engine` and `blockchecks.checkers` — see
[architecture.md](architecture.md). Persistence: **`engine/store/`**
(`RunStateStore` / `SqliteRunStore`). `db_logger.py` is a deprecation shim only.

## Quality

```bash
pip install -e ".[dev,discovery]"
ruff check src tests
pytest -m "not integration"
```

## Deprecated

- `tmp-scripts/README.md` architecture section → use [architecture.md](architecture.md)
- `engine/db_logger.py` — re-export shim; use `engine/store/`
- ~~`pair_runner.py` / `pair_manager.py`~~ — **removed** (post-1.0.0 audit)
