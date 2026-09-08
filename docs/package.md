# Package structure — blockcheckS

Аудит layout после 1.4.0 (lua_bridge-only campaign, service split, 2026-08-28).
Счётчики обновлены 2026-09-08 (волна 1.4.1: аудит §1–§13, mcp/server, gc).

## Канон

```
blockcheckS/
├── src/blockchecks/
│   ├── __init__.py
│   ├── bs.py                  # thin CLI entry → cli.parser.main
│   ├── terminal.py            # color output (supports_color, C, error/warn/heading)
│   ├── cli/
│   │   ├── parser.py          # argparse + add_campaign_args (scan/pair/full)
│   │   ├── profiles.py        # --profile smoke|fast|20h bundles
│   │   ├── presets.py
│   │   └── commands/          # tcp, udp, pair, ...
│   ├── main.py                # bs full orchestrator
│   ├── nfconf.py
│   ├── harvest_batch.py       # harvest-batch manifest v1 + batch.txt export
│   ├── engine/
│   │   ├── run_spec.py        # RunSpec + CampaignContext (typed CLI config)
│   │   ├── paths.py           # XDG dirs (config/data/cache)
│   │   ├── store/             # RunStateStore DAO (sqlite)
│   │   ├── ggc_pool.py        # googlevideo SNI pool (synthetic/real/fixed)
│   │   ├── domain_quarantine.py # mid-run dead-domain exclusion
│   │   ├── probe_executors.py # curl/udp probe dispatch backends
│   │   ├── pair_matrix_runner.py # TCP×UDP pair matrix phase
│   │   ├── bridge_worker_pool.py # lua_bridge worker scheduling
│   │   ├── config.py
│   │   ├── fail_phase.py      # FailPhase enum (32 tokens) + classifier
│   │   ├── triage.py          # TriageProfile (preflight interference profile)
│   │   ├── generators/        # StrategyItem + Standard facade + families/
│   │   │   └── families/      # split.py / fake.py / tamper.py / _helpers.py (StrategyParams)
│   │   ├── matrix_generator.py  # facade: generate_tcp/udp
│   │   ├── conf_builder.py    # single-source nfqws2 arg sanitization
│   │   ├── async_runner.py
│   │   └── ...
│   └── checkers/
│       ├── l3_probe.py        # L3/L4 SYN/ICMP blackhole probe
│       ├── quic_raw.py        # raw QUIC Initial drop probe
│       ├── curl_probe.py      # stream-triage + TLS-profile probes
│       └── ...
├── service/                   # ← on disk this lives under src/blockchecks/service/
│   ├── probe.py               # invoke_curl_probe_worker (netns subprocess API)
│   ├── probe_service.py       # resident on-the-fly probe service
│   ├── server.py              # Unix-socket core + HTTP bridge
│   ├── live_events.py         # events_live.jsonl + current_probe.json
│   ├── metrics.py             # nfqws2 RSS monitor, PID-scoped pkill
│   ├── ns_firewall.py         # per-netns iptables OUTPUT rules
│   ├── lua_bridge_ipc.py      # nfqws2 Lua bridge IPC (+ TTL-RST events)
│   ├── nfqws2.py              # start_daemon / Nfqws2Manager
│   ├── nfqws2_launcher.py     # Popen + bind-retry
│   ├── nfqws2_settle.py       # wait_nfqws2_ready / _wait_nfqws2_gone
│   ├── in_ns_workers.py       # subprocess curl/UDP worker (--mode curl|udp)
│   └── test_runner.py         # oneshot host/netns TestRunner
├── configs/                   # repo-root .conf (CONFIGS_DIR)
├── presets/                   # manifest.toml registry + domains/ + strategies/
├── tests/
├── scripts/                   # campaign runners, systemd, blobs (not in wheel)
├── dev/                       # smokes, gate_all, benches (not in wheel / CI)
├── docs/
└── pyproject.toml
```

Entry points: `bs` → `blockchecks.bs:main`, `bs-mcp` → `blockchecks.mcp:main`,
`bc-main` → `blockchecks.main:main`, `bc-nfconf` → `blockchecks.nfconf:main`.

## Path resolution & configs policy (ONB-7)

**Recommended:** `pip install .` (wheel) — no git checkout needed.

`PROJECT_DIR` in `config.py` resolves repo root (parent of `src/`) for an
editable install, otherwise probes the distutils *data* roots that a wheel
carries baked data to via `[tool.setuptools.data-files]`:
`sys.prefix/blockchecks`, `sys.prefix/local/blockchecks` (Debian/Ubuntu system
Python) and `site.getuserbase()/blockchecks` (`pip install --user`). Arbitrary
`pip install --prefix=...` targets are not probed (runtime cannot know a
foreign prefix without PYTHONPATH). The wheel is self-sufficient. Runtime paths:

- `configs/*.conf` — at `PROJECT_DIR` (repo root, or the wheel data root: `sys.prefix[/local]/blockchecks`, `~/.local/blockchecks`)
- `presets/` — shipped catalog at `PROJECT_DIR` (same roots)
- **Runtime data (XDG):**
  - `~/.config/blockcheckS/config.toml` — user defaults
  - `~/.config/blockcheckS/presets/` — reserved (`USER_PRESETS_DIR`)
  - `~/.config/blockcheckS/presets/ipset/` — CIDR catalog overlay (first-run copy)
  - `~/.local/state/blockcheckS/state.db` — run state DB (default `--db`)
  - `~/.local/state/blockcheckS/logs/` — runtime logs
  - `~/.local/state/blockcheckS/presets/` — reserved (`USER_DATA_PRESETS_DIR`)
  - `~/.local/share/blockcheckS/data_block/providers/<slug>/` — live provider store
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
bs ──► cli.parser + cli.cliapp (argparse) ──► commands + async_runner / service.test_runner
     └── add_campaign_args (scan/pair/full) + profiles.apply_profile
main ──► RunSpec.from_args ──► CampaignContext ──► async_runner + nfconf
async_runner ──► service.probe.invoke_curl_probe_worker ──► service.in_ns_workers --mode curl|udp
in_ns_workers ──► checkers + service.netns_pool + service.nfqws2
matrix_generator ──► generators/* (standard facade → families/)
```

Canonical pair path: `bs pair` → `async_runner`.

## Public API

Re-exported from `blockchecks.engine` and `blockchecks.checkers` — see
[architecture.md](architecture.md). Persistence: **`engine/store/`**
(`RunStateStore` / `SqliteRunStore`). `db_logger.py` is a deprecation shim only.

## Repository Structure & Metrics

Full tree with line counts (Python / shell / lua / md; binaries excluded).
Suite: **2291 tests** — unit **2106 collected**, quality **165**, integration **19** (sudo E2E).

```
src/blockchecks/                      (≈39 100 строк, 143 py-файла)
├── bs.py 14 | terminal.py 113 | main.py 169 | main_phases.py 1281 | nfconf.py 439
├── harvest_batch.py 310 | provider_import.py 234 | shortlist_export.py 198 | shortlist_import.py 217
├── cli/  cliapp.py 423 | parser.py 1409 | profiles.py 107 | presets.py 66 | user_config.py 132
│   └── commands/  bench_settle 161 | data_block 34 | gc 48 | harvest_batch 71 | mcp 22 |
│                  pair 246 | pair_phases 1046 | preflight 211 | serve 94 | stop 18 |
│                  tcp 124 | udp 128
├── checkers/  composite_runner 10 | curl_probe 1117 | dns_secure 733 | fooling_probe 180 |
│   http3 158 | ip_block 175 | ip_pin 94 | l3_probe 162 | port_block 79 | quic_raw 199 |
│   tcp_tls 289 | ttl_probe 121 | udp_voice 246 | voice_discovery 407 | voice_dns 602 |
│   youtube_url 191
├── data_block/  export 95 | provider 317 | store 594
├── engine/  adaptive_queue 657 | adaptive_runner 347 | async_runner 542 | blob_aliases 277 |
│   blob_filter 140 | bridge_worker_pool 292 | byedpi_matrix_generator 129 | byedpi_translator 334 |
│   composite_runner 270 | conf_builder 723 | config 507 | db_logger 22 (shim) | dns_pin_service 140 |
│   domain_loader 243 | domain_quarantine 265 | fail_phase 173 | family_axes 352 | family_needs 202 |
│   family_registry 199 | family_spec 176 | gc 409 | ggc_pool 345 | ipset_catalog 363 | log 353 |
│   matrix_generator 350 | nfqws_config 88 | pair_matrix_runner 276 | paths 363 | preflight 959 |
│   preset_paths 151 | probe_executors 546 | probe_result_logger 190 | results 100 | resume_triage 35 |
│   run_deadline 149 | run_finalize 212 | run_spec 213 | secure_io 32 | settings 232 |
│   settle_profile 194 | static_validator 301 | strategy_loader 103 | system_deps 518 |
│   tcp_fanout 111 | triage 260 | wssize_retry 39
│   ├── generators/  base 41 | custom 248 | flowseal 369 | standard 262
│   │   └── families/  fake 293 | split 325 | tamper 332 | _helpers 197
│   └── store/  models 16 | schema 285 | sqlite_store 1391
├── mcp/  server 1475
├── service/  batch_bridge_probe 175 | batch_models 71 | batch_scheduler 125 | batch_service 607 |
│   firewall 5 | in_ns_workers 854 | live_events 211 | lua_bridge_ipc 473 | lua_conf 126 |
│   lua_netns 57 | lua_session 192 | metrics 406 | netns_pool 548 | nfqws2 201 |
│   nfqws2_launcher 389 | nfqws2_settle 193 | ns_firewall 266 | probe 313 | probe_service 219 |
│   run_control 238 | server 1033 | test_runner 432
tests/unit/                        (≈33 200 строк, 143 файла)   — 2106 collected
tests/integration/                 (≈640 строк, 5 файлов)       — 19 (sudo)
lua/blockchecks/                   (≈310 строк): geneva 76 | scan_bridge 95 | write_ipc 90 |
                                   init 4 | custom/dupfake 49
scripts/                           (≈1 600 строк, 16 скриптов) — кампании, install, пресеты
dev/                               (≈2 800 строк, 27 скриптов) — смоки, гейты, бенчи
blobs/                             (31 .bin + README 68)  — verify_blobs 31 OK
presets/                           manifest.toml + domains 12 + strategies 27 + ipset 3 + README
systemd/                           blockcheck-series.service 18 | blockcheck-serve.service 18
docs/                              (≈5 970 строк, 17 md + cookbook 5)
```

Biggest modules: `mcp/server` 1475 | `parser` 1409 | `sqlite_store` 1391 | `main_phases` 1281 |
`curl_probe` 1117 | `dns_secure` 733 | `conf_builder` 723 | `adaptive_queue` 657 |
`batch_service` 607 | `voice_dns` 602.

## Quality

```bash
pip install -e ".[dev,discovery]"
ruff check src tests
pytest -m "not integration"
bash dev/gate_all.sh                 # unit + quality + ruff + vulture
```

## Deprecated

- `tmp-scripts/README.md` architecture section → use [architecture.md](architecture.md)
- `engine/db_logger.py` — re-export shim; use `engine/store/`
- ~~`pair_runner.py` / `pair_manager.py`~~ — **removed** (post-1.0.0 audit)
