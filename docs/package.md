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
│   │   ├── fail_phase.py      # FailPhase enum (32 tokens) + classifier
│   │   ├── triage.py          # TriageProfile (preflight interference profile)
│   │   ├── generators/        # StrategyItem + Standard/Flowseal/Custom
│   │   ├── matrix_generator.py  # facade: generate_tcp/udp
│   │   ├── async_runner.py
│   │   ├── test_runner.py
│   │   ├── _probe_worker.py   # subprocess curl probe (no sys.path hack)
│   │   └── ...
│   └── checkers/
│       ├── l3_probe.py        # L3/L4 SYN/ICMP blackhole probe
│       ├── quic_raw.py        # raw QUIC Initial drop probe
│       ├── curl_probe.py      # stream-triage + TLS-profile probes
│       └── ...
├── service/
│   ├── probe_service.py       # resident on-the-fly probe service
│   ├── server.py              # Unix-socket core + HTTP bridge
│   └── lua_bridge_ipc.py      # nfqws2 Lua bridge IPC (+ TTL-RST events)
├── configs/                   # repo-root .conf (CONFIGS_DIR)
├── presets/
├── tests/
├── docs/
└── pyproject.toml
```

Entry points: `bs` → `blockchecks.bs:main`, `bc-main`, `bc-nfconf`.

## Path resolution & configs policy (ONB-7)

**Recommended:** `pip install -e .` from git checkout.

`PROJECT_DIR` in `config.py` resolves repo root (parent of `src/`). For a plain
`pip install` wheel (no checkout), it falls back to `sys.prefix/blockchecks`,
where `[tool.setuptools.data-files]` ships `blobs/`, `configs/`, `lua/` and
`presets/` — the wheel is self-sufficient. Runtime paths:

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
Since 1.2.1a the wheel also carries baked data via `[tool.setuptools.data-files]`,
so a plain `pip install` wheel is self-sufficient (no editable install / clone
needed). `BLOCKCHECKS_BLOBS`/`BLOCKCHECKS_LUA_DIR` still override at runtime.

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

## Repository Structure & Metrics

Full tree with line counts (Python / shell / lua / md; binaries excluded).
Unit suite: **1097 passed**, quality **113**, integration **17** (sudo E2E).

```
src/blockchecks/                      (≈23 600 строк, 98 py-файлов)
├── bs.py 17 | main.py 234 | main_phases.py 1091 | nfconf.py 229
├── provider_import.py 230 | shortlist_export.py 188 | shortlist_import.py 206
├── cli/  cliapp.py 581 | parser.py 835 | presets.py 65 | user_config.py 104
│   └── commands/  bench_settle 161 | pair 208 | pair_phases 802 | serve 62 |
│                  stop 14 | tcp 117 | udp 123
├── checkers/  composite_runner 189 | curl_probe 938 | dns_secure 497 |
│   http3 92 | ip_block 173 | ip_pin 106 | l3_probe 167 | port_block 76 |
│   quic_raw 178 | tcp_tls 211 | udp_voice 219 | voice_discovery 342 |
│   voice_dns 562 | youtube_url 195
├── data_block/  provider 167 | store 362
├── engine/  adaptive_queue 468 | adaptive_runner 347 | async_runner 1004 |
│   blob_aliases 169 | byedpi_matrix_generator 144 | byedpi_translator 323 |
│   conf_builder 279 | config 433 | db_logger 22 | domain_loader 175 |
│   fail_phase 128 | family_needs 192 | in_ns_workers 672 | matrix_generator 287 |
│   nfqws_config 129 | paths 322 | preflight 487 | preset_paths 101 |
│   results 82 | run_deadline 144 | run_finalize 154 | secure_io 24 |
│   settings 107 | settle_profile 178 | strategy_loader 64 | system_deps 489 |
│   tcp_fanout 100 | test_runner 353 | triage 130
│   ├── generators/  base 41 | custom 155 | flowseal 335 | standard 1583
│   └── store/  models 16 | schema 201 | sqlite_store 716
├── service/  batch_bridge_probe 186 | batch_models 67 | batch_scheduler 110 |
│   batch_service 385 | firewall 120 | lua_bridge_ipc 128 | lua_conf 158 |
│   lua_netns 82 | lua_session 141 | metrics 216 | netns_pool 228 | nfqws2 308 |
│   nfqws2_settle 53 | probe 105 | probe_service 219 | run_control 178 | server 181
tests/unit/                        (≈16 800 строк, 107 файлов)  — 1097 passed
tests/integration/                 (≈430 строк, 3 файла)        — 17 passed (sudo)
lua/blockchecks/                   (≈200 строк): geneva 65 | scan_bridge 90 |
                                   write_ipc 44 | init 3
scripts/                           (≈1 500 строк, 23 скрипта)
blobs/                             (31 .bin + README 68)  — verify_blobs 31 OK
presets/                           domains 13 + strategies 29 + README 180
systemd/                           blockcheck-series.service 18 | blockcheck-serve.service 18
docs/                              (≈3 200 строк, 10 md + cookbook 5)
```

Biggest modules: `main_phases` 1091 | `async_runner` 1004 | `curl_probe` 938 |
`parser` 835 | `pair_phases` 802 | `sqlite_store` 716 | `in_ns_workers` 672 |
`cliapp` 581 | `system_deps` 489 | `preflight` 487 | `config` 433.

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
