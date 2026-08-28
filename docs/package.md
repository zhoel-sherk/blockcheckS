# Package structure — blockcheckS

Аудит layout после 1.4.0 (lua_bridge-only campaign, service split, 2026-08-28).

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
├── service/
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
bs ──► cli.parser (pydantic CliApp) ──► commands + async_runner / service.test_runner
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
Unit suite: **1938 collected**, quality **165**, integration **22** (sudo E2E).

```
src/blockchecks/                      (≈25 700 строк, 108+ py-файлов)
├── bs.py 17 | terminal.py 97 | main.py 234 | main_phases.py 1102 | nfconf.py 229
├── harvest_batch.py 310 | provider_import.py 230 | shortlist_export.py 188 | shortlist_import.py 206
├── cli/  cliapp.py 602 | parser.py 1293 | profiles.py 46 | presets.py 65 | user_config.py 104
│   └── commands/  bench_settle 161 | pair 208 | pair_phases 802 | serve 62 |
│                  stop 14 | tcp 117 | udp 123
├── checkers/  composite_runner 189 | curl_probe 941 | dns_secure 497 |
│   http3 92 | ip_block 173 | ip_pin 106 | l3_probe 167 | port_block 76 |
│   quic_raw 178 | tcp_tls 211 | udp_voice 219 | voice_discovery 342 |
│   voice_dns 562 | youtube_url 195
├── data_block/  provider 167 | store 362
├── engine/  adaptive_queue 468 | adaptive_runner 353 | async_runner 1007 |
│   bridge_worker_pool 273 | blob_aliases 169 | byedpi_matrix_generator 144 |
│   byedpi_translator 323 | conf_builder 361 | config 433 | db_logger 22 |
│   domain_loader 175 | domain_quarantine 168 | fail_phase 128 | family_needs 192 |
│   ggc_pool 317 | matrix_generator 287 | nfqws_config 94 |
│   pair_matrix_runner 271 | paths 322 | preflight 487 | probe_executors 531 |
│   preset_paths 101 | results 82 | run_deadline 144 | run_finalize 154 |
│   run_spec 185 | secure_io 24 | settings 107 | settle_profile 178 | strategy_loader 64 |
│   system_deps 489 | tcp_fanout 100 | triage 130
│   ├── generators/  base 41 | custom 155 | flowseal 335 | standard 882 (facade)
│   │   └── families/  fake 213 | split 253 | tamper 244 | _helpers 112
│   └── store/  models 16 | schema 277 | sqlite_store 1269
├── service/  batch_bridge_probe 186 | batch_models 67 | batch_scheduler 110 |
│   batch_service 385 | firewall 120 | live_events 211 | lua_bridge_ipc 458 |
│   lua_conf 112 | lua_netns 82 | lua_session 141 | metrics 334 |
│   netns_pool 228 | ns_firewall 211 | nfqws2 200 | nfqws2_launcher 370 |
│   nfqws2_settle 71 | probe 107 | probe_service 219 | run_control 178 | server 181 |
│   in_ns_workers 842 | test_runner 419
tests/unit/                        (≈18 600 строк, 141 файла)   — 1938 collected
tests/integration/                 (≈670 строк, 5 файлов)       — 22 passed (sudo)
lua/blockchecks/                   (≈200 строк): geneva 65 | scan_bridge 90 |
                                   write_ipc 44 | init 3
scripts/                           (≈1 000 строк, 14 скриптов + README) — кампании, install, пресеты
dev/                               (≈1 700 строк, 19 скриптов + README) — смоки, гейты, бенчи
blobs/                             (31 .bin + README 68)  — verify_blobs 31 OK
presets/                           manifest.toml + domains 11 + strategies 27 + README 180
systemd/                           blockcheck-series.service 18 | blockcheck-serve.service 18
docs/                              (≈3 560 строк, 9 md + cookbook 5)
```

Biggest modules: `parser` 1293 | `sqlite_store` 1269 | `main_phases` 1102 | `async_runner` 1007 | `curl_probe` 941 |
`in_ns_workers` 842 | `pair_phases` 802 | `cliapp` 602 | `system_deps` 489 | `preflight` 487 | `lua_bridge_ipc` 458.

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
